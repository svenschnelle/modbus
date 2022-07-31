#define _XOPEN_SOURCE 600
#include <time.h>
#include <stdio.h>
#include <modbus/modbus.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define MSEC(x) ((x)*1000000)

typedef enum {
	BUTTON_RELEASED,
	BUTTON_PRESS_SHORT,
	BUTTON_PRESS_LONG,
} button_state_t;

typedef enum {
	TASTER_WZ_LINKS_HOCH,
	TASTER_WZ_LINKS_RUNTER,
	TASTER_WZ_RECHTS_HOCH,
	TASTER_WZ_RECHTS_RUNTER,
	TASTER_WZ_LICHT_OBEN,
	TASTER_WZ_LICHT_UNTEN,
	TASTER_ESSDIELE_HOCH,
	TASTER_ESSDIELE_RUNTER,
	TASTER_KUECHE_TUER_HOCH,
	TASTER_KUECHE_TUER_RUNTER,
	TASTER_KUECHE_FENSTER_HOCH,
	TASTER_KUECHE_FENSTER_RUNTER,
	TASTER_BUERO_INES_HOCH,
	TASTER_BUERO_INES_RUNTER,
	TASTER_SZ_HOCH,
	TASTER_SZ_RUNTER,
	TASTER_BAD_HOCH,
	TASTER_BAD_RUNTER,
	TASTER_WC_HOCH,
	TASTER_WC_RUNTER,
	TASTER_GAESTE_HOCH,
	TASTER_GAESTE_RUNTER,
	TASTER_DG_BAD_SEITE_HOCH,
	TASTER_DG_BAD_SEITE_RUNTER,
	TASTER_DG_BAD_DACH_HOCH,
	TASTER_DG_BAD_DACH_RUNTER,
	TASTER_DG_MITTE_OBEN_HOCH,
	TASTER_DG_MITTE_OBEN_RUNTER,
	TASTER_DG_MITTE_UNTEN_HOCH,
	TASTER_DG_MITTE_UNTEN_RUNTER,
	TASTER_DG_ALEX_DACH1_HOCH,
	TASTER_DG_ALEX_DACH1_RUNTER,
	TASTER_DG_ALEX_DACH2_HOCH,
	TASTER_DG_ALEX_DACH2_RUNTER,
	TASTER_DG_ALEX_SEITE_HOCH,
	TASTER_DG_ALEX_SEITE_RUNTER,
	TASTER_DG_RINI_DACH1_HOCH,
	TASTER_DG_RINI_DACH1_RUNTER,
	TASTER_DG_RINI_DACH2_HOCH,
	TASTER_DG_RINI_DACH2_RUNTER,
	TASTER_DG_RINI_SEITE_HOCH,
	TASTER_DG_RINI_SEITE_RUNTER,
} input_t;

#define DEBUG(...) fprintf(stderr, __VA_ARGS__);

#define BUTTON(name, num)				\
	{ name, num, 0, BUTTON_RELEASED, {0}, {0} }
struct button {
	const char *name;
	int bitnum;
	bool old_state;
	button_state_t state;
	struct timespec pressed;
	struct timespec released;
} buttons[] = {
	[TASTER_WZ_LINKS_HOCH] = BUTTON("Wohnzimmer Links hoch", 17),
	[TASTER_WZ_LINKS_RUNTER] = BUTTON("Wohnzimmer Links runter", 16),
	[TASTER_WZ_RECHTS_HOCH] = BUTTON("Wohnzimmer Rechts hoch", 19),
	[TASTER_WZ_RECHTS_RUNTER] = BUTTON("Wohnzimmer Rechts runter", 18),
	[TASTER_WZ_LICHT_OBEN] = BUTTON("Licht WZ oben", 21),
	[TASTER_WZ_LICHT_UNTEN] = BUTTON("Licht WZ unten", 20),
	[TASTER_ESSDIELE_HOCH] = BUTTON("Essdiele hoch", 15),
	[TASTER_ESSDIELE_RUNTER] = BUTTON("Essdiele runter", 14),
	[TASTER_KUECHE_TUER_HOCH] = BUTTON("Kueche Tuer hoch", 3),
	[TASTER_KUECHE_TUER_RUNTER] = BUTTON("Kueche Tuer runter", 2),
	[TASTER_KUECHE_FENSTER_HOCH] = BUTTON("Kueche Fenster hoch", 1),
	[TASTER_KUECHE_FENSTER_RUNTER] = BUTTON("Kueche Fenster runter", 0),
	[TASTER_BUERO_INES_RUNTER] = BUTTON("Buero Ines runter", 6),
	[TASTER_BUERO_INES_HOCH] = BUTTON("Buero Ines hoch", 7),
	[TASTER_SZ_HOCH] = BUTTON("Schlafzimmer hoch", 9),
	[TASTER_SZ_RUNTER] = BUTTON("Schlafzimmer runter", 8),
	[TASTER_WC_HOCH] = BUTTON("WC hoch", 5),
	[TASTER_WC_RUNTER] = BUTTON("WC runter", 4),
	[TASTER_BAD_HOCH] = BUTTON("Bad hoch", 11),
	[TASTER_BAD_RUNTER] = BUTTON("Bad runter", 10),
	[TASTER_GAESTE_HOCH] = BUTTON("Gaeste hoch", 128+4),
	[TASTER_GAESTE_RUNTER] = BUTTON("Gaeste runter", 128+5),
	[TASTER_DG_BAD_DACH_HOCH] = BUTTON("DG Bad Dach hoch", 128+2),
	[TASTER_DG_BAD_DACH_RUNTER] = BUTTON("DG Bad Dach runter", 128+3),
	[TASTER_DG_BAD_SEITE_HOCH] = BUTTON("DG Bad Seite hoch", 128+0),
	[TASTER_DG_BAD_SEITE_RUNTER] = BUTTON("DG Bad Seite runter", 128+1),
	[TASTER_DG_MITTE_OBEN_HOCH] = BUTTON("DG Mitte oben hoch", 128+6),
	[TASTER_DG_MITTE_OBEN_RUNTER] = BUTTON("DG Mitte oben runter", 128+7),
	[TASTER_DG_MITTE_UNTEN_HOCH] = BUTTON("DG Mitte unten hoch", 128+8),
	[TASTER_DG_MITTE_UNTEN_RUNTER] = BUTTON("DG Mitte unten runter", 128+9),
	[TASTER_DG_ALEX_DACH1_HOCH] = BUTTON("DG Alex Dach1 hoch", 128+10),
	[TASTER_DG_ALEX_DACH1_RUNTER] = BUTTON("DG Alex Dach1 runter", 128+10),
	[TASTER_DG_ALEX_DACH2_HOCH] = BUTTON("DG Alex Dach2 hoch", 128+12),
	[TASTER_DG_ALEX_DACH2_RUNTER] = BUTTON("DG Alex Dach2 runter", 128+13),
	[TASTER_DG_ALEX_SEITE_HOCH] = BUTTON("DG Alex Seite hoch", 128+14),
	[TASTER_DG_ALEX_SEITE_RUNTER] = BUTTON("DG Alex Seite runter", 128+15),
	[TASTER_DG_RINI_DACH1_HOCH] = BUTTON("DG Rini Dach1 hoch", 128+16),
	[TASTER_DG_RINI_DACH1_RUNTER] = BUTTON("DG Rini Dach1 runter", 128+17),
	[TASTER_DG_RINI_DACH2_HOCH] = BUTTON("DG Rini Dach2 hoch", 128+18),
	[TASTER_DG_RINI_DACH2_RUNTER] = BUTTON("DG Rini Dach2 runter", 128+19),
	[TASTER_DG_RINI_SEITE_HOCH] = BUTTON("DG Rini Seite hoch", 128+20),
	[TASTER_DG_RINI_SEITE_RUNTER] = BUTTON("DG Rini Seite runter", 128+21),
};

static bool get_input(uint8_t *data, int input)
{
	return data[input >> 3] & (1 << (input & 7));
}

static double diff_timespec(const struct timespec *time1, const struct timespec *time0) {
  return (time1->tv_sec - time0->tv_sec)
      + (time1->tv_nsec - time0->tv_nsec) / 1000000000.0;
}

static void update_buttons(uint16_t *bits, struct timespec *now)
{
	for (unsigned int i = 0; i < ARRAY_SIZE(buttons); i++) {
		struct button *b = buttons + i;
		bool state = get_input((void *)bits, b->bitnum);
		if (state ^ b->old_state) {
			b->old_state = state;
			if (state) {
				b->pressed = *now;
				b->state = BUTTON_PRESS_SHORT;
				DEBUG("%s: short press\n", b->name);
			} else {
					b->released = *now;
					b->state = BUTTON_RELEASED;
					DEBUG("%s: released\n", b->name);
			}
		}
		if (state && b->old_state && diff_timespec(now, &b->pressed) > 0.250) {
			b->state = BUTTON_PRESS_LONG;
			DEBUG("%s: long press\n", b->name);
		}
	}
}

int main(void)
{
	modbus_t *mb[2];
	uint16_t inputs[32] = { 0 };
	struct timespec now, req, rem;

	mb[0] = modbus_new_tcp("192.168.0.5", 502);
	mb[1] = modbus_new_tcp("192.168.0.6", 502);
	modbus_connect(mb[0]);
	modbus_connect(mb[1]);

	for(;;) {
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			fprintf(stderr, "clock_gettime: %m\n");
			goto out;
		}
		modbus_read_registers(mb[0], 0, 8, inputs);
		modbus_read_registers(mb[1], 0, 8, inputs + 8);
		printf("%ld.%ld: ", now.tv_sec, now.tv_nsec);
		for (int i = 0; i < 32; i++)
			printf(" %04X", inputs[i]);
		update_buttons(inputs, &now);
		printf("\n");
		req.tv_sec = 0;
		req.tv_nsec = 20000000;
		while (nanosleep(&req, &rem) == -1 && errno == EINTR)
			req = rem;

	}
out:
	modbus_close(mb[0]);
	modbus_free(mb[0]);
	modbus_close(mb[1]);
	modbus_free(mb[1]);

}
