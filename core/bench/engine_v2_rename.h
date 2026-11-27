/* Rename the exported engine API for the second variant of engine.c.
 *
 * core/bench/engine_ab.c links two builds of engine.c into one process so the
 * two variants can be measured interleaved at round granularity.  Interleaving
 * inside one process is what makes the comparison usable on a shared host: a
 * hypervisor neighbour stealing memory bandwidth inflates a whole second of
 * measurements, so cross-process A/B runs only reproduce to tens of percent.
 *
 * The baseline TU is compiled with
 *   -include core/bench/engine_v2_rename.h
 * so every exported symbol of that copy gets a _v2 suffix and cannot collide
 * with the engine under test (which keeps the canonical names).
 *
 * Keep this list in sync with the extern declarations at the top of
 * engine_ab.c and with the exported symbols of engine.o.
 */
#ifndef TR_ENGINE_V2_RENAME_H
#define TR_ENGINE_V2_RENAME_H

#define tr_drop_reason_name tr_drop_reason_name_v2
#define tr_engine_apply tr_engine_apply_v2
#define tr_engine_capture_start tr_engine_capture_start_v2
#define tr_engine_capture_status tr_engine_capture_status_v2
#define tr_engine_capture_stop tr_engine_capture_stop_v2
#define tr_engine_config_copy tr_engine_config_copy_v2
#define tr_engine_config_env tr_engine_config_env_v2
#define tr_engine_create tr_engine_create_v2
#define tr_engine_destroy tr_engine_destroy_v2
#define tr_engine_housekeeping tr_engine_housekeeping_v2
#define tr_engine_input tr_engine_input_v2
#define tr_engine_input_burst tr_engine_input_burst_v2
#define tr_engine_ping tr_engine_ping_v2
#define tr_engine_send_router_solicitations tr_engine_send_router_solicitations_v2
#define tr_engine_set_tx tr_engine_set_tx_v2
#define tr_engine_set_tx_ipv4_cksum tr_engine_set_tx_ipv4_cksum_v2
#define tr_engine_show tr_engine_show_v2
#define tr_engine_stats_text tr_engine_stats_text_v2
#define tr_engine_traceroute tr_engine_traceroute_v2

#endif
