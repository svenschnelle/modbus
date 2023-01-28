#define _XOPEN_SOURCE 600
#include <time.h>
#include <stdio.h>
#include <modbus/modbus.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include "timespec.h"
#include <json-c/json.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/inotify.h>

#ifdef SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#define MSEC(x) ((x) * 1000 * 1000)
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

static int shouldexit;

typedef enum {
	BUTTON_RELEASED,
	BUTTON_PRESS_SHORT,
	BUTTON_PRESS_LONG,
} button_state_t;

struct input {
	struct modbus_coupler *coupler;
	int bitnum;
	bool old_state;
	button_state_t state;
	struct timespec pressed;
	struct timespec released;
	void (*update_handler)(struct input *);
};

struct output {
	struct modbus_coupler *coupler;
	struct timespec time_off;

	int bitnum;
	bool state;
};

struct modbus_coupler {
	char *id;
	char *ip;
	int port;
	uint8_t data_in[32];
	uint8_t data_out[32]; // FIXME: dynamic alloc
	int data_in_len;
	int data_out_len;
	modbus_t *modbus;
};

struct blind {
	char *name;
	bool automatic_up;
	bool automatic_down;
	int runtime_up;
	int runtime_down;
	time_t up_not_before;
	time_t time_up;
	time_t time_down;
	struct output output_up;
	struct output output_down;
	struct input input_up;
	struct input input_down;
	struct timespec last_update;
};

struct config {
	struct modbus_coupler *couplers;
	struct blind *blinds;
	int coupler_count;
	int blind_count;
};

#define DEBUG(...) fprintf(stderr, __VA_ARGS__);

#if 0
struct button buttons[] = {
	BUTTON(TASTER_WZ_LICHT_OBEN, "Licht WZ oben", 21, button_press_handler),
	BUTTON(TASTER_WZ_LICHT_UNTEN, "Licht WZ unten", 20, button_press_handler),
};
#endif

static bool get_output_bit(uint8_t *data, uint32_t output)
{
	return data[output >> 3] & (1 << (output & 7));
}

static void set_output_bit(uint8_t *data, uint32_t output, bool state)
{
	if (state)
		data[output >> 3] |= (1 << (output & 7));
	else
		data[output >> 3] &= ~(1 << (output & 7));
}

static bool update_output(const char *name, struct output *output, struct timespec *now)
{
	bool old_state = get_output_bit(output->coupler->data_out, output->bitnum);
	bool ret = false;

	if (old_state != output->state) {
		DEBUG("%s: %s.%d: %s set to %d\n", __func__,
		      output->coupler->id, output->bitnum, name, output->state);
		set_output_bit(output->coupler->data_out, output->bitnum, output->state);
		ret = true;
	}

	if (old_state && output->state && timespec_gt(*now, output->time_off)) {
		DEBUG("%s: %s.%d: %s timeout expired\n", __func__,
		      output->coupler->id, output->bitnum, name);
		set_output_bit(output->coupler->data_out, output->bitnum, false);
		output->state = false;
		ret = true;
	}
	return ret;
}

static bool update_outputs(struct config *config, struct timespec *now)
{
	bool ret = false;
	struct blind *b;
	int i;

	for (i = 0; i < config->blind_count; i++) {
		b = config->blinds + i;
		update_output(b->name, &b->output_up, now);
		update_output(b->name, &b->output_down, now);
	}
	return ret;
}

static bool get_input(uint8_t *data, uint32_t input)
{
	return data[input >> 3] & (1 << (input & 7));
}

static void set_output(struct output *output, bool state, struct timespec *off)
{
	DEBUG("%s: %s.%d = %d\n", __func__, output->coupler->id, output->bitnum, state);
	output->state = state;
	if (off)
		output->time_off = *off;
	else
		output->time_off.tv_sec = -1;
}

static int update_input(const char *name, struct input *input, struct timespec *now)
{
	bool state, changed = false;

	state = get_input(input->coupler->data_in, input->bitnum);

	if (state ^ input->old_state) {
		input->old_state = state;
		if (state) {
			input->pressed = *now;
			input->state = BUTTON_PRESS_SHORT;
			DEBUG("%s.%d: %s short press\n", input->coupler->id, input->bitnum, name);
		} else {
			input->released = *now;
			input->state = BUTTON_RELEASED;
			DEBUG("%s.%d: %s released\n", input->coupler->id, input->bitnum, name);
		}
		changed = true;
	}

	if (state && input->old_state && timespec_to_ms(timespec_sub(*now, input->pressed)) > 250) {
		input->state = BUTTON_PRESS_LONG;
		DEBUG("%s.%d: %s long press\n", input->coupler->id, input->bitnum, name);
		changed = true;
	}
	return changed;
}

static void update_blind_button(struct blind *b, struct timespec *now)
{
	struct timespec end = { 0, 0 };

	if (update_input(b->name, &b->input_up, now) ||
	    update_input(b->name, &b->input_down, now)) {
		if (b->input_up.state != BUTTON_RELEASED &&
		    b->input_down.state != BUTTON_RELEASED)
			return;

		switch (b->input_up.state) {
		case BUTTON_PRESS_SHORT:
			end.tv_sec = b->runtime_up;
			end = timespec_add(*now, end);
			if (!b->output_down.state)
				set_output(&b->output_up, true, &end);
			set_output(&b->output_down, false, NULL);
			break;

		case BUTTON_PRESS_LONG:
			end.tv_nsec = 250000000;
			end = timespec_add(*now, end);
			if (!b->output_down.state)
				set_output(&b->output_up, true, &end);
			set_output(&b->output_down, false, NULL);
			break;

		default:
			break;
		}

		switch (b->input_down.state) {
		case BUTTON_PRESS_SHORT:
			end.tv_sec = b->runtime_up;
			end = timespec_add(*now, end);
			if (!b->output_up.state)
				set_output(&b->output_down, true, &end);
			set_output(&b->output_up, false, NULL);
			break;

		case BUTTON_PRESS_LONG:
			end.tv_nsec = 250000000;
			end = timespec_add(*now, end);
			set_output(&b->output_up, false, NULL);
			if (!b->output_up.state)
				set_output(&b->output_down, true, &end);
			break;

		default:
			break;
		}
	}
}

static void update_blind_auto(struct blind *b, struct timespec *now)
{
	struct timespec end = { 0, 0 }, ts = { 60, 0 };
	unsigned int tod;
	struct tm tm;
	time_t ltime;

	ltime = time(NULL);
	if (!localtime_r(&ltime, &tm)) {
		fprintf(stderr, "localtime failed\n");
		return;
	}

	tod = tm.tm_hour * 3600 + tm.tm_min * 60;
	if (tod == b->time_up) {
		DEBUG("auto_up matched\n");
		end.tv_sec += b->runtime_up;
		end = timespec_add(*now, end);
		set_output(&b->output_up, true, &end);
		set_output(&b->output_down, false, NULL);
		b->last_update = timespec_add(*now, ts);
	}

	if (tod == b->time_down) {
		DEBUG("auto_down matched\n");
		end.tv_sec += b->runtime_down;
		end = timespec_add(*now, end);
		set_output(&b->output_down, true, &end);
		set_output(&b->output_up, false, NULL);
		b->last_update = timespec_add(*now, ts);

	}
}

static void update_blinds(struct config *config, struct timespec *now)
{
	struct blind *b;
	int i;

	for (i = 0; i < config->blind_count; i++) {
		b = config->blinds + i;
		update_blind_button(b, now);
		if (timespec_le(b->last_update, *now))
			update_blind_auto(b, now);
	}
}

static void free_config(struct config *config)
{
	struct modbus_coupler *c;
	struct blind *b;
	int i;

	if (!config)
		return;

	for(i = 0; i < config->coupler_count; i++) {
		c = config->couplers + i;
		modbus_free(c->modbus);
		free(c->id);
		free(c->ip);
	}

	for(i = 0; i < config->blind_count; i++) {
		b = config->blinds + i;
		free(b->name);
	}
	free(config->blinds);
	free(config->couplers);
	free(config);
}

static int json_get_time(const char *parent, struct json_object *obj, const char *name)
{
	struct json_object *tmp;
	const char *p, *p2;
	struct tm tm;

	tmp = json_object_object_get(obj, name);
	if (!tmp) {
		fprintf(stderr, "%s: %s/%s: failed to get time object\n",
			__func__, parent, name);
		return -1;
	}

	p = json_object_get_string(tmp);
	if (!p) {
		fprintf(stderr, "%s: %s/%s: failed to get string\n",
			__func__, parent, name);
		return -1;
	}

	if (!strlen(p))
		return -1;

	p2 = strptime(p, "%H:%M", &tm);
	if (!p2 || *p2 != '\0') {
		fprintf(stderr, "%s: %s/%s: failed to parse time %s\n",
			__func__, parent, name, p);
		return -1;
	}
	return tm.tm_hour * 3600 + tm.tm_min * 60;
}

static int json_get_int_with_default(struct json_object *obj, const char *name, int dflt)
{
	struct json_object *tmp = json_object_object_get(obj, name);
	if (!tmp)
		return dflt;
	return json_object_get_int(tmp);
}

static struct modbus_coupler *get_coupler_by_id(struct config *config, const char *id)
{
	int i;

	for (i = 0; i < config->coupler_count; i++) {
		if (!strcmp(config->couplers[i].id, id))
			return &config->couplers[i];
	}
	return NULL;
}

static int json_parse_output(struct json_object *obj, struct config *config, const char *name, struct output *output)
{
	struct json_object *tmp, *tmp2;
	const char *p;

	tmp = json_object_object_get(obj, name);
	if (!tmp)
		return -1;

	tmp2 = json_object_object_get(tmp, "id");
	if (!tmp2)
		return -1;

	p = json_object_get_string(tmp2);
	if (!p)
		return -1;

	output->coupler = get_coupler_by_id(config, p);
	tmp2 = json_object_object_get(tmp, "bit");
	if (!tmp)
		return -1;
	output->bitnum = json_object_get_int(tmp2);
	return 0;
}

static int json_parse_input(struct json_object *obj,
			    struct config *config,
			    const char *name,
			    struct input *input)
{
	struct json_object *tmp, *tmp2;
	const char *p;

	tmp = json_object_object_get(obj, name);
	if (!tmp)
		return -1;

	tmp2 = json_object_object_get(tmp, "id");
	if (!tmp2)
		return -1;

	p = json_object_get_string(tmp2);
	if (!p)
		return -1;

	input->coupler = get_coupler_by_id(config, p);
	tmp2 = json_object_object_get(tmp, "bit");
	if (!tmp)
		return -1;
	input->bitnum = json_object_get_int(tmp2);
	return 0;
}

static int parse_blind(struct config *config,
		       struct json_object *obj,
		       struct blind *blind)
{
	struct json_object *tmp;

	tmp = json_object_object_get(obj, "name");
	if (!tmp) {
		fprintf(stderr, "failed to get name field from blind config\n");
		return -1;
	}
	blind->name = strdup(json_object_get_string(tmp));
	if (!blind->name)
		return -1;

	tmp = json_object_object_get(obj, "automatic_up");
	if (!tmp) {
		fprintf(stderr, "failed to get automatic_up field from blind config\n");
		return -1;
	}
	blind->automatic_up = json_get_int_with_default(obj, "automatic_up", 0);
	blind->automatic_down = json_get_int_with_default(obj, "automatic_up", 0);
	blind->runtime_up = json_get_int_with_default(obj, "runtime_up", 90);
	blind->runtime_down = json_get_int_with_default(obj, "runtime_down", 90);
	blind->time_up = json_get_time(blind->name, obj, "time_up");
	blind->time_down = json_get_time(blind->name, obj, "time_down");
	blind->up_not_before = json_get_time(blind->name, obj, "not_up_before");
	json_parse_output(obj, config, "output_up", &blind->output_up);
	json_parse_output(obj, config, "output_down", &blind->output_down);
	json_parse_input(obj, config, "input_up", &blind->input_up);
	json_parse_input(obj, config, "input_down", &blind->input_down);
	return 0;
}

static int parse_coupler(struct json_object *obj, struct modbus_coupler *coupler)
{
	struct json_object *tmp;

	tmp = json_object_object_get(obj, "id");
	if (!tmp) {
		fprintf(stderr, "failed to get id field from modbus coupler config\n");
		return -1;
	}
	coupler->id = strdup(json_object_get_string(tmp));
	if (!coupler->id)
		return -1;

	tmp = json_object_object_get(obj, "ip");
	if (!tmp) {
		fprintf(stderr, "failed to get ip field from modbus coupler config\n");
		return -1;
	}
	coupler->ip = strdup(json_object_get_string(tmp));
	if (!coupler->ip)
		return -1;
	coupler->port = 502;
	tmp = json_object_object_get(obj, "port");
	if (tmp)
		coupler->port = json_object_get_int(tmp);

	return 0;
}

static struct config *parse_config(struct json_object *obj)
{
	struct config *ret;
	struct json_object *tmp;
	int i, len;

	ret = calloc(1, sizeof(struct config));
	if (!ret)
		return NULL;

	tmp = json_object_object_get(obj, "couplers");
	len = json_object_array_length(tmp);
	ret->couplers = calloc(len, sizeof(struct modbus_coupler));
	if (!ret->couplers)
		goto out;
	ret->coupler_count = len;
	for (i = 0; i < len; i++)
		if (parse_coupler(json_object_array_get_idx(tmp, i), &ret->couplers[i]) == -1)
			goto out;

	tmp = json_object_object_get(obj, "blinds");
	len = json_object_array_length(tmp);
	ret->blinds = calloc(len, sizeof(struct blind));
	if (!ret->blinds)
		goto out;
	ret->blind_count = len;
	for (i = 0; i < len; i++)
		if (parse_blind(ret, json_object_array_get_idx(tmp, i), &ret->blinds[i]) == -1)
			goto out;

	return ret;
out:
	free_config(ret);
	return NULL;
}

static struct config *read_config(void)
{
	struct config *ret = NULL;
	struct stat statbuf;
	struct json_object *obj;
	char *buf;
	int fd;

	fd = open("config.json", O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "open config.json: %m\n");
		goto out;
	}

	if (fstat(fd, &statbuf) == -1) {
		fprintf(stderr, "fstat config.json: %m\n");
		goto out;
	}

	buf = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED) {
		fprintf(stderr, "mmap: %m\n");
		goto out;
	}
	obj = json_tokener_parse(buf);
	ret = parse_config(obj);
	json_object_put(obj);
out:
	if (fd != -1)
		close(fd);
	return ret;
}

static int check_inotify(int fd, int wd)
{
	struct inotify_event event;

	ssize_t len = read(fd, &event, sizeof(event));
	if (len == -1) {
		if (errno != EAGAIN)
			fprintf(stderr, "read from inotify fd: %m\n");
		return -1;
	}

	if (len < (ssize_t)sizeof(event)) {
		fprintf(stderr, "short read from inotify fd\n");
		return -1;
	}
	return event.wd == wd;
}

static void signal_handler(int sig)
{
	(void)sig;

	shouldexit = 1;
}

int main(void)
{
	struct timespec now, req, rem;
	struct modbus_coupler *coupler;
	struct config *config = NULL, *config_new;
	int i, ifd, wd;
	int watchdog_cnt = 0, ready_signaled;
	ifd = inotify_init1(IN_NONBLOCK);
	if (ifd == -1) {
		fprintf(stderr, "failed to create inotify fd: %m\n");
		return 1;
	}

	wd = inotify_add_watch(ifd, "config.json", IN_CLOSE_WRITE);
	if (wd == -1) {
		fprintf(stderr, "failed to add config.json watch: %m\n");
		close(ifd);
		return 1;
	}

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	while(!shouldexit) {
		if (!config || check_inotify(ifd, wd) == 1) {
#ifdef SYSTEMD
			sd_notifyf(0, "RELOADING=1\n");
			ready_signaled=0;
#endif
			config_new = read_config();
			if (config_new) {
				free_config(config);
				config = config_new;
				for (i = 0; i < config->coupler_count; i++) {
					coupler = config->couplers + i;
					coupler->modbus = modbus_new_tcp(coupler->ip, coupler->port);
					modbus_connect(coupler->modbus);
				}
				DEBUG("config reload done\n");
			} else {
				fprintf(stderr, "config reload failed\n");
			}
		}

		if (!config) {
			sleep(10);
			continue;
		}

		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			fprintf(stderr, "clock_gettime: %m\n");
			goto out;
		}

		for (i = 0; i < config->coupler_count; i++) {
			coupler = config->couplers + i;
			modbus_read_registers(coupler->modbus, 0, 8, (uint16_t *)&coupler->data_in);
//			for (i = 0; i < 16; i++)
//				DEBUG(" %02X", coupler->data_in[i]);
//			DEBUG("\n");
		}
		update_blinds(config, &now);
		update_outputs(config, &now);

		for (i = 0; i < config->coupler_count; i++) {
			coupler = config->couplers + i;
//			for (i = 0; i < 16; i++)
//				DEBUG(" %02X", coupler->data_out[i]);
//			DEBUG("\n");
			modbus_write_registers(coupler->modbus, 0, 8, (uint16_t *)&coupler->data_out);
		}
#ifdef SYSTEMD
		if (!ready_signaled) {
			sd_notifyf(0, "READY=1\n"
					"STATUS=Processing requests...\n"
					"MAINPID=%lu",
			   (unsigned long) getpid());
			ready_signaled = 1;
		}
		if (watchdog_cnt++ > 100) {
			watchdog_cnt = 0;
			sd_notifyf(0, "WATCHDOG=1\n");

		}
#endif
		req.tv_sec = 0;
		req.tv_nsec = MSEC(50);
		while (nanosleep(&req, &rem) == -1 && errno == EINTR)
			req = rem;
	}
	free_config(config);
out:
}
