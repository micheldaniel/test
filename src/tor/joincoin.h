/* Copyright (c) 2014, LOOP Developers */
/* See LICENSE for licensing information */

/**
 * \file LOOP.h
 * \brief Headers for LOOP.cpp
 **/

#ifndef TOR_LOOP_H
#define TOR_LOOP_H

#ifdef __cplusplus
extern "C" {
#endif

    char const* LOOP_tor_data_directory(
    );

    char const* LOOP_service_directory(
    );

    int check_interrupted(
    );

    void set_initialized(
    );

    void wait_initialized(
    );

#ifdef __cplusplus
}
#endif

#endif

