/*
 * Copyright (C) 2015, Wazuh Inc.
 * May 04, 2022
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef STATEREMOTE_H
#define STATEREMOTE_H

#include <stdint.h>

/* Status structures */

typedef struct _ctrl_msgs_t {
    uint64_t keepalive_count;
    uint32_t startup_count;
    uint32_t shutdown_count;
    uint32_t request_count;
} ctrl_msgs_t;

typedef struct _recv_msgs_t {
    uint64_t evt_count;
    uint64_t ctrl_count;
    uint32_t ping_count;
    uint32_t unknown_count;
    uint32_t dequeued_count;
    uint32_t discarded_count;
    ctrl_msgs_t ctrl_breakdown;
} recv_msgs_t;

typedef struct _sent_msgs_t {
    uint64_t queued_count;
    uint64_t ack_count;
    uint64_t shared_count;
    uint32_t ar_count;
    uint32_t cfga_count;
    uint32_t request_count;
    uint32_t discarded_count;
} sent_msgs_t;

typedef struct _remoted_state_t {
    uint32_t tcp_sessions;
    uint64_t recv_bytes;
    uint64_t sent_bytes;
    uint32_t keys_reload_count;
    uint32_t update_shared_files_count;
    recv_msgs_t recv_breakdown;
    sent_msgs_t sent_breakdown;
} remoted_state_t;


/* Status functions */

/**
 * @brief Main function of remoted status writer
 * @return void* NULL
 */
void* rem_state_main();

/**
 * @brief Increment TCP sessions counter
 */
void rem_inc_tcp();

/**
 * @brief Decrement TCP sessions counter
 */
void rem_dec_tcp();

/**
 * @brief Increment bytes received
 * @param bytes Number of bytes to increment
 */
void rem_add_recv(unsigned long bytes);

/**
 * @brief Increment received event messages counter
 */
void rem_inc_recv_evt();

/**
 * @brief Increment received control messages counter
 */
void rem_inc_recv_ctrl();

/**
 * @brief Increment received ping messages counter
 */
void rem_inc_recv_ping();

/**
 * @brief Increment received unknown messages counter
 */
void rem_inc_recv_unknown();

/**
 * @brief Increment received dequeued after closed messages counter
 */
void rem_inc_recv_dequeued();

/**
 * @brief Increment received discarded messages counter
 */
void rem_inc_recv_discarded();

/**
 * @brief Increment received keepalive control messages counter
 */
void rem_inc_recv_ctrl_keepalive();

/**
 * @brief Increment received startup control messages counter
 */
void rem_inc_recv_ctrl_startup();

/**
 * @brief Increment received shutdown control messages counter
 */
void rem_inc_recv_ctrl_shutdown();

/**
 * @brief Increment received request control messages counter
 */
void rem_inc_recv_ctrl_request();

/**
 * @brief Increment bytes sent
 * @param bytes Number of bytes to increment
 */
void rem_add_send(unsigned long bytes);

/**
 * @brief Increment sent queued messages counter
 */
void rem_inc_send_queued();

/**
 * @brief Increment sent ack messages counter
 */
void rem_inc_send_ack();

/**
 * @brief Increment sent shared file messages counter
 */
void rem_inc_send_shared();

/**
 * @brief Increment sent AR messages counter
 */
void rem_inc_send_ar();

/**
 * @brief Increment sent CFGA messages counter
 */
void rem_inc_send_cfga();

/**
 * @brief Increment sent request messages counter
 */
void rem_inc_send_request();

/**
 * @brief Increment sent discarded messages counter
 */
void rem_inc_send_discarded();

/**
 * @brief Increment keys reload counter
 */
void rem_inc_keys_reload();

/**
 * @brief Increment update shared files counter
 */
void rem_inc_update_shared_files();

#endif
