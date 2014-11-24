package com.bejibx.encryption;

import java.util.Arrays;

/**
 * Created by Maksimov on 22.08.2014.
 *
 * Implementation of ARIA cryptographic algorithm.
 * ARIA is a block cipher designed in 2003 by a large group of South Korean researchers.
 * In 2004, the Korean Agency for Technology and Standards selected it as a standard cryptographic technique.
 *
 * The algorithm uses a substitution-permutation network structure based on AES. The interface is the same
 * as AES: 128-bit block size with key size of 128, 192, or 256 bits. The number of rounds is 12, 14, or 16,
 * depending on the key size. ARIA uses two 8×8-bit S-boxes and their inverses in alternate rounds;
 * one of these is the Rijndael S-box.
 *
 * The key schedule processes the key using a 3-round 256-bit Feistel cipher, with the binary expansion of 1/π
 * as a source of "nothing up my sleeve numbers".
 *
 * http://en.wikipedia.org/wiki/ARIA_(cipher)
 *
 * Comments in the middle of the code are taken from http://tools.ietf.org/html/rfc5794.
 */
public class AriaCipher
{
/*
 *  Independent Submission                                                                                      J. Lee
 *  Request for Comments: 5794                                                                                  J. Lee
 *  Category: Informational                                                                                     J. Kim
 *  ISSN: 2070-1721                                                                                            D. Kwon
 *                                                                                                              C. Kim
 *                                                                                                                NSRI
 *                                                                                                          March 2010
 *  Copyright Notice ---------------------------------------------------------------------------------------------------
 *
 *      Copyright (c) 2010 IETF Trust and the persons identified as the
 *      document authors.  All rights reserved.
 *
 *      This document is subject to BCP 78 and the IETF Trust's Legal
 *      Provisions Relating to IETF Documents
 *      (http://trustee.ietf.org/license-info) in effect on the date of
 *      publication of this document.  Please review these documents
 *      carefully, as they describe your rights and restrictions with respect
 *      to this document.
 *  --------------------------------------------------------------------------------------------------------------------
 */
    /**
     * Encryption round keys.
     */
    private byte[][] mEK;

    /**
     * Decryption round keys.
     */
    private byte[][] mDK;

    /**
     * Number of rounds. The number of rounds depends on the size of the master key.
     */
    private byte mNumberRounds;

    /**
     * Master-key length in bytes
     */
    private int mKeyLength;

    //@formatter:off
    // See key scheduling part.
    private static final byte[] C1 = {
                   0x51,        0x7c, (byte) 0xc1, (byte) 0xb7,
                   0x27,        0x22,        0x0a, (byte) 0x94,
            (byte) 0xfe,        0x13, (byte) 0xab, (byte) 0xe8,
            (byte) 0xfa, (byte) 0x9a,        0x6e, (byte) 0xe0
    };

    private static final byte[] C2 = {
                   0x6d, (byte) 0xb1,        0x4a, (byte) 0xcc,
            (byte) 0x9e,        0x21, (byte) 0xc8,        0x20,
            (byte) 0xff,        0x28, (byte) 0xb1, (byte) 0xd5,
            (byte) 0xef,        0x5d, (byte) 0xe2, (byte) 0xb0
    };

    private static final byte[] C3 = {
            (byte) 0xdb, (byte) 0x92,        0x37, 0x1d,
                   0x21,        0x26, (byte) 0xe9, 0x70,
                   0x03,        0x24, (byte) 0x97, 0x75,
                   0x04, (byte) 0xe8, (byte) 0xc9, 0x0e
    };

   /*
    * 2.4.2.  Substitution Layers --------------------------------------------------------------------------------------
    *
    *    ARIA has two types of substitution layers that alternate between
    *    rounds.  Type 1 is used in the odd rounds, and type 2 is used in the
    *    even rounds.
    *
    *    Type 1 substitution layer SL1 is an algorithm that takes a 16-byte
    *    string x0 || x1 ||...|| x15 as input and outputs a 16-byte string
    *    y0 || y1 ||...|| y15 as follows.
    *
    *    y0 = SB1(x0),  y1 = SB2(x1),  y2 = SB3(x2),  y3 = SB4(x3),
    *    y4 = SB1(x4),  y5 = SB2(x5),  y6 = SB3(x6),  y7 = SB4(x7),
    *    y8 = SB1(x8),  y9 = SB2(x9),  y10= SB3(x10), y11= SB4(x11),
    *    y12= SB1(x12), y13= SB2(x13), y14= SB3(x14), y15= SB4(x15).
    *
    *    Type 2 substitution layer SL2 is an algorithm that takes a 16-byte
    *    string x0 || x1 ||...|| x15 as input and outputs a 16-byte string
    *    y0 || y1 ||...|| y15 as follows.
    *
    *    y0 = SB3(x0),  y1 = SB4(x1),  y2 = SB1(x2),  y3 = SB2(x3),
    *    y4 = SB3(x4),  y5 = SB4(x5),  y6 = SB1(x6),  y7 = SB2(x7),
    *    y8 = SB3(x8),  y9 = SB4(x9),  y10= SB1(x10), y11= SB2(x11),
    *    y12= SB3(x12), y13= SB4(x13), y14= SB1(x14), y15= SB2(x15).
    *
    *    Here, SB1, SB2, SB3, and SB4 are S-boxes that take an 8-bit string as
    *    input and output an 8-bit string.  These S-boxes are defined by the
    *    following look-up tables.
    *
    *       SB1:
    *           0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    *        00 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
    *        10 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
    *        20 b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
    *        30 04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
    *        40 09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
    *        50 53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
    *        60 d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
    *        70 51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
    *        80 cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
    *        90 60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
    *        a0 e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
    *        b0 e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
    *        c0 ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
    *        d0 70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
    *        e0 e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
    *        f0 8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16
    *
    *       SB2:
    *           0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    *        00 e2 4e 54 fc 94 c2 4a cc 62 0d 6a 46 3c 4d 8b d1
    *        10 5e fa 64 cb b4 97 be 2b bc 77 2e 03 d3 19 59 c1
    *        20 1d 06 41 6b 55 f0 99 69 ea 9c 18 ae 63 df e7 bb
    *        30 00 73 66 fb 96 4c 85 e4 3a 09 45 aa 0f ee 10 eb
    *        40 2d 7f f4 29 ac cf ad 91 8d 78 c8 95 f9 2f ce cd
    *        50 08 7a 88 38 5c 83 2a 28 47 db b8 c7 93 a4 12 53
    *        60 ff 87 0e 31 36 21 58 48 01 8e 37 74 32 ca e9 b1
    *        70 b7 ab 0c d7 c4 56 42 26 07 98 60 d9 b6 b9 11 40
    *        80 ec 20 8c bd a0 c9 84 04 49 23 f1 4f 50 1f 13 dc
    *        90 d8 c0 9e 57 e3 c3 7b 65 3b 02 8f 3e e8 25 92 e5
    *        a0 15 dd fd 17 a9 bf d4 9a 7e c5 39 67 fe 76 9d 43
    *        b0 a7 e1 d0 f5 68 f2 1b 34 70 05 a3 8a d5 79 86 a8
    *        c0 30 c6 51 4b 1e a6 27 f6 35 d2 6e 24 16 82 5f da
    *        d0 e6 75 a2 ef 2c b2 1c 9f 5d 6f 80 0a 72 44 9b 6c
    *        e0 90 0b 5b 33 7d 5a 52 f3 61 a1 f7 b0 d6 3f 7c 6d
    *        f0 ed 14 e0 a5 3d 22 b3 f8 89 de 71 1a af ba b5 81
    *
    *       SB3:
    *           0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    *        00 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb
    *        10 7c e3 39 82 9b 2f ff 87 34 8e 43 44 c4 de e9 cb
    *        20 54 7b 94 32 a6 c2 23 3d ee 4c 95 0b 42 fa c3 4e
    *        30 08 2e a1 66 28 d9 24 b2 76 5b a2 49 6d 8b d1 25
    *        40 72 f8 f6 64 86 68 98 16 d4 a4 5c cc 5d 65 b6 92
    *        50 6c 70 48 50 fd ed b9 da 5e 15 46 57 a7 8d 9d 84
    *        60 90 d8 ab 00 8c bc d3 0a f7 e4 58 05 b8 b3 45 06
    *        70 d0 2c 1e 8f ca 3f 0f 02 c1 af bd 03 01 13 8a 6b
    *        80 3a 91 11 41 4f 67 dc ea 97 f2 cf ce f0 b4 e6 73
    *        90 96 ac 74 22 e7 ad 35 85 e2 f9 37 e8 1c 75 df 6e
    *        a0 47 f1 1a 71 1d 29 c5 89 6f b7 62 0e aa 18 be 1b
    *        b0 fc 56 3e 4b c6 d2 79 20 9a db c0 fe 78 cd 5a f4
    *        c0 1f dd a8 33 88 07 c7 31 b1 12 10 59 27 80 ec 5f
    *        d0 60 51 7f a9 19 b5 4a 0d 2d e5 7a 9f 93 c9 9c ef
    *        e0 a0 e0 3b 4d ae 2a f5 b0 c8 eb bb 3c 83 53 99 61
    *        f0 17 2b 04 7e ba 77 d6 26 e1 69 14 63 55 21 0c 7d
    *
    *       SB4:
    *           0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    *        00 30 68 99 1b 87 b9 21 78 50 39 db e1 72  9 62 3c
    *        10 3e 7e 5e 8e f1 a0 cc a3 2a 1d fb b6 d6 20 c4 8d
    *        20 81 65 f5 89 cb 9d 77 c6 57 43 56 17 d4 40 1a 4d
    *        30 c0 63 6c e3 b7 c8 64 6a 53 aa 38 98 0c f4 9b ed
    *        40 7f 22 76 af dd 3a 0b 58 67 88 06 c3 35 0d 01 8b
    *        50 8c c2 e6 5f 02 24 75 93 66 1e e5 e2 54 d8 10 ce
    *        60 7a e8 08 2c 12 97 32 ab b4 27 0a 23 df ef ca d9
    *        70 b8 fa dc 31 6b d1 ad 19 49 bd 51 96 ee e4 a8 41
    *        80 da ff cd 55 86 36 be 61 52 f8 bb 0e 82 48 69 9a
    *        90 e0 47 9e 5c 04 4b 34 15 79 26 a7 de 29 ae 92 d7
    *        a0 84 e9 d2 ba 5d f3 c5 b0 bf a4 3b 71 44 46 2b fc
    *        b0 eb 6f d5 f6 14 fe 7c 70 5a 7d fd 2f 18 83 16 a5
    *        c0 91 1f 05 95 74 a9 c1 5b 4a 85 6d 13 07 4f 4e 45
    *        d0 b2 0f c9 1c a6 bc ec 73 90 7b cf 59 8f a1 f9 2d
    *        e0 f2 b1 00 94 37 9f d0 2e 9c 6e 28 3f 80 f0 3d d3
    *        f0 25 8a b5 e7 42 b3 c7 ea f7 4c 11 33 03 a2 ac 60
    *
    *    For example, SB1(0x23) = 0x26 and SB4(0xef) = 0xd3.  Note that SB3
    *    and SB4 are the inverse functions of SB1 and SB2, respectively, and
    *    accordingly SL2 is the inverse of SL1.
    * ------------------------------------------------------------------------------------------------------------------
    */
    /**
     * S-box 1
     */
    private static final byte[] SB1 = {
    /*                        0            1            2            3            4            5            6            7            8            9            a            b            c            d            e            f  */
    /* 00 */               0x63,        0x7c,        0x77,        0x7b, (byte) 0xf2,        0x6b,        0x6f, (byte) 0xc5,        0x30,        0x01,        0x67,        0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab,        0x76,
    /* 10 */        (byte) 0xca, (byte) 0x82, (byte) 0xc9,        0x7d, (byte) 0xfa,        0x59,        0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4,        0x72, (byte) 0xc0,
    /* 20 */        (byte) 0xb7, (byte) 0xfd, (byte) 0x93,        0x26,        0x36,        0x3f, (byte) 0xf7, (byte) 0xcc,        0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1,        0x71, (byte) 0xd8,        0x31,        0x15,
    /* 30 */               0x04, (byte) 0xc7,        0x23, (byte) 0xc3,        0x18, (byte) 0x96,        0x05, (byte) 0x9a,        0x07,        0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb,        0x27, (byte) 0xb2,        0x75,
    /* 40 */               0x09, (byte) 0x83,        0x2c,        0x1a,        0x1b,        0x6e,        0x5a, (byte) 0xa0,        0x52,        0x3b, (byte) 0xd6, (byte) 0xb3,        0x29, (byte) 0xe3,        0x2f, (byte) 0x84,
    /* 50 */               0x53, (byte) 0xd1,        0x00, (byte) 0xed,        0x20, (byte) 0xfc, (byte) 0xb1,        0x5b,        0x6a, (byte) 0xcb, (byte) 0xbe,        0x39,        0x4a,        0x4c,        0x58, (byte) 0xcf,
    /* 60 */        (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb,        0x43,        0x4d,        0x33, (byte) 0x85,        0x45, (byte) 0xf9,        0x02,        0x7f,        0x50,        0x3c, (byte) 0x9f, (byte) 0xa8,
    /* 70 */               0x51, (byte) 0xa3,        0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d,        0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda,        0x21,        0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2,
    /* 80 */        (byte) 0xcd,        0x0c,        0x13, (byte) 0xec,        0x5f, (byte) 0x97,        0x44,        0x17, (byte) 0xc4, (byte) 0xa7,        0x7e,        0x3d,        0x64,        0x5d,        0x19,        0x73,
    /* 90 */               0x60, (byte) 0x81,        0x4f, (byte) 0xdc,        0x22,        0x2a, (byte) 0x90, (byte) 0x88,        0x46, (byte) 0xee, (byte) 0xb8,        0x14, (byte) 0xde,        0x5e,        0x0b, (byte) 0xdb,
    /* A0 */        (byte) 0xe0,        0x32,        0x3a,        0x0a,        0x49,        0x06,        0x24,        0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac,        0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4,        0x79,
    /* B0 */        (byte) 0xe7, (byte) 0xc8,        0x37,        0x6d, (byte) 0x8d, (byte) 0xd5,        0x4e, (byte) 0xa9,        0x6c,        0x56, (byte) 0xf4, (byte) 0xea,        0x65,        0x7a, (byte) 0xae,        0x08,
    /* C0 */        (byte) 0xba,        0x78,        0x25,        0x2e,        0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd,        0x74,        0x1f,        0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a,
    /* D0 */               0x70,        0x3e, (byte) 0xb5,        0x66,        0x48,        0x03, (byte) 0xf6,        0x0e,        0x61,        0x35,        0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1,        0x1d, (byte) 0x9e,
    /* E0 */        (byte) 0xe1, (byte) 0xf8, (byte) 0x98,        0x11,        0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b,        0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce,        0x55,        0x28, (byte) 0xdf,
    /* F0 */        (byte) 0x8c, (byte) 0xa1, (byte) 0x89,        0x0d, (byte) 0xbf, (byte) 0xe6,        0x42,        0x68,        0x41, (byte) 0x99,        0x2d,        0x0f, (byte) 0xb0,        0x54, (byte) 0xbb,        0x16
    };

    /**
     * S-box 2
     */
    private static final byte[] SB2 = {
    /*                        0            1            2            3            4            5            6            7            8            9            a            b            c            d            e            f  */
	/* 00 */        (byte) 0xe2,        0x4e,        0x54, (byte) 0xfc, (byte) 0x94, (byte) 0xc2,        0x4a, (byte) 0xcc,        0x62,        0x0d,        0x6a,        0x46,        0x3c,        0x4d, (byte) 0x8b, (byte) 0xd1,
	/* 10 */               0x5e, (byte) 0xfa,        0x64, (byte) 0xcb, (byte) 0xb4, (byte) 0x97, (byte) 0xbe,        0x2b, (byte) 0xbc,        0x77,        0x2e,        0x03, (byte) 0xd3,        0x19,        0x59, (byte) 0xc1,
	/* 20 */               0x1d,        0x06,        0x41,        0x6b,        0x55, (byte) 0xf0, (byte) 0x99,        0x69, (byte) 0xea, (byte) 0x9c,        0x18, (byte) 0xae,        0x63, (byte) 0xdf, (byte) 0xe7, (byte) 0xbb,
	/* 30 */               0x00,        0x73,        0x66, (byte) 0xfb, (byte) 0x96,        0x4c, (byte) 0x85, (byte) 0xe4,        0x3a,        0x09,        0x45, (byte) 0xaa,        0x0f, (byte) 0xee,        0x10, (byte) 0xeb,
	/* 40 */               0x2d,        0x7f, (byte) 0xf4,        0x29, (byte) 0xac, (byte) 0xcf, (byte) 0xad, (byte) 0x91, (byte) 0x8d,        0x78, (byte) 0xc8, (byte) 0x95, (byte) 0xf9,        0x2f, (byte) 0xce, (byte) 0xcd,
	/* 50 */               0x08,        0x7a, (byte) 0x88,        0x38,        0x5c, (byte) 0x83,        0x2a,        0x28,        0x47, (byte) 0xdb, (byte) 0xb8, (byte) 0xc7, (byte) 0x93, (byte) 0xa4,        0x12,        0x53,
	/* 60 */        (byte) 0xff, (byte) 0x87,        0x0e,        0x31,        0x36,        0x21,        0x58,        0x48,        0x01, (byte) 0x8e,        0x37,        0x74,        0x32, (byte) 0xca, (byte) 0xe9, (byte) 0xb1,
	/* 70 */        (byte) 0xb7, (byte) 0xab,        0x0c, (byte) 0xd7, (byte) 0xc4,        0x56,        0x42,        0x26,        0x07, (byte) 0x98,        0x60, (byte) 0xd9, (byte) 0xb6, (byte) 0xb9,        0x11,        0x40,
	/* 80 */        (byte) 0xec,        0x20, (byte) 0x8c, (byte) 0xbd, (byte) 0xa0, (byte) 0xc9, (byte) 0x84,        0x04,        0x49,        0x23, (byte) 0xf1,        0x4f,        0x50,        0x1f,        0x13, (byte) 0xdc,
	/* 90 */        (byte) 0xd8, (byte) 0xc0, (byte) 0x9e,        0x57, (byte) 0xe3, (byte) 0xc3,        0x7b,        0x65,        0x3b,        0x02, (byte) 0x8f,        0x3e, (byte) 0xe8,        0x25, (byte) 0x92, (byte) 0xe5,
	/* A0 */               0x15, (byte) 0xdd, (byte) 0xfd,        0x17, (byte) 0xa9, (byte) 0xbf, (byte) 0xd4, (byte) 0x9a,        0x7e, (byte) 0xc5,        0x39,        0x67, (byte) 0xfe,        0x76, (byte) 0x9d,        0x43,
	/* B0 */        (byte) 0xa7, (byte) 0xe1, (byte) 0xd0, (byte) 0xf5,        0x68, (byte) 0xf2,        0x1b,        0x34,        0x70,        0x05, (byte) 0xa3, (byte) 0x8a, (byte) 0xd5,        0x79, (byte) 0x86, (byte) 0xa8,
	/* C0 */               0x30, (byte) 0xc6,        0x51,        0x4b,        0x1e, (byte) 0xa6,        0x27, (byte) 0xf6,        0x35, (byte) 0xd2,        0x6e,        0x24,        0x16, (byte) 0x82,        0x5f, (byte) 0xda,
	/* D0 */        (byte) 0xe6,        0x75, (byte) 0xa2, (byte) 0xef,        0x2c, (byte) 0xb2,        0x1c, (byte) 0x9f,        0x5d,        0x6f, (byte) 0x80,        0x0a,        0x72,        0x44, (byte) 0x9b,        0x6c,
	/* E0 */        (byte) 0x90,        0x0b,        0x5b,        0x33,        0x7d,        0x5a,        0x52, (byte) 0xf3,        0x61, (byte) 0xa1, (byte) 0xf7, (byte) 0xb0, (byte) 0xd6,        0x3f,        0x7c,        0x6d,
	/* F0 */        (byte) 0xed,        0x14, (byte) 0xe0, (byte) 0xa5,        0x3d,        0x22, (byte) 0xb3, (byte) 0xf8, (byte) 0x89, (byte) 0xde,        0x71,        0x1a, (byte) 0xaf, (byte) 0xba, (byte) 0xb5, (byte) 0x81
    };

    /**
     * S-box 3
     */
    private static final byte[] SB3 = {
    /*                        0            1            2            3            4            5            6            7            8            9            a            b            c            d            e            f  */
    /* 00 */               0x52,        0x09,        0x6a, (byte) 0xd5,        0x30,        0x36, (byte) 0xa5,        0x38, (byte) 0xbf,        0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb,
    /* 10 */               0x7c, (byte) 0xe3,        0x39, (byte) 0x82, (byte) 0x9b,        0x2f, (byte) 0xff, (byte) 0x87,        0x34, (byte) 0x8e,        0x43,        0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb,
    /* 20 */               0x54,        0x7b, (byte) 0x94,        0x32, (byte) 0xa6, (byte) 0xc2,        0x23,        0x3d, (byte) 0xee,        0x4c, (byte) 0x95,        0x0b,        0x42, (byte) 0xfa, (byte) 0xc3,        0x4e,
    /* 30 */               0x08,        0x2e, (byte) 0xa1,        0x66,        0x28, (byte) 0xd9,        0x24, (byte) 0xb2,        0x76,        0x5b, (byte) 0xa2,        0x49,        0x6d, (byte) 0x8b, (byte) 0xd1,        0x25,
    /* 40 */               0x72, (byte) 0xf8, (byte) 0xf6,        0x64, (byte) 0x86,        0x68, (byte) 0x98,        0x16, (byte) 0xd4, (byte) 0xa4,        0x5c, (byte) 0xcc,        0x5d,        0x65, (byte) 0xb6, (byte) 0x92,
    /* 50 */               0x6c,        0x70,        0x48,        0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda,        0x5e,        0x15,        0x46,        0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84,
    /* 60 */        (byte) 0x90, (byte) 0xd8, (byte) 0xab,        0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3,        0x0a, (byte) 0xf7, (byte) 0xe4,        0x58,        0x05, (byte) 0xb8, (byte) 0xb3,        0x45,        0x06,
    /* 70 */        (byte) 0xd0,        0x2c,        0x1e, (byte) 0x8f, (byte) 0xca,        0x3f,        0x0f,        0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd,        0x03,        0x01,        0x13, (byte) 0x8a,        0x6b,
    /* 80 */               0x3a, (byte) 0x91,        0x11,        0x41,        0x4f,        0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6,        0x73,
    /* 90 */        (byte) 0x96, (byte) 0xac,        0x74,        0x22, (byte) 0xe7, (byte) 0xad,        0x35, (byte) 0x85, (byte) 0xe2, (byte) 0xf9,        0x37, (byte) 0xe8,        0x1c,        0x75, (byte) 0xdf,        0x6e,
    /* A0 */               0x47, (byte) 0xf1,        0x1a,        0x71,        0x1d,        0x29, (byte) 0xc5, (byte) 0x89,        0x6f, (byte) 0xb7,        0x62,        0x0e, (byte) 0xaa,        0x18, (byte) 0xbe,        0x1b,
    /* B0 */        (byte) 0xfc,        0x56,        0x3e,        0x4b, (byte) 0xc6, (byte) 0xd2,        0x79,        0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe,        0x78, (byte) 0xcd,        0x5a, (byte) 0xf4,
    /* C0 */               0x1f, (byte) 0xdd, (byte) 0xa8,        0x33, (byte) 0x88,        0x07, (byte) 0xc7,        0x31, (byte) 0xb1,        0x12,        0x10,        0x59,        0x27, (byte) 0x80, (byte) 0xec,        0x5f,
    /* D0 */               0x60,        0x51,        0x7f, (byte) 0xa9,        0x19, (byte) 0xb5,        0x4a,        0x0d,        0x2d, (byte) 0xe5,        0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef,
    /* E0 */        (byte) 0xa0, (byte) 0xe0,        0x3b,        0x4d, (byte) 0xae,        0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb,        0x3c, (byte) 0x83,        0x53, (byte) 0x99,        0x61,
    /* F0 */               0x17,        0x2b,        0x04,        0x7e, (byte) 0xba,        0x77, (byte) 0xd6,        0x26, (byte) 0xe1,        0x69,        0x14,        0x63,        0x55,        0x21,        0x0c,        0x7d
    };

    /**
     * S-box 4
     */
    private static final byte[] SB4 = {
    /*                        0            1            2            3            4            5            6            7            8            9            a            b            c            d            e            f  */
    /* 00 */               0x30,        0x68, (byte) 0x99,        0x1b, (byte) 0x87, (byte) 0xb9,        0x21,        0x78,        0x50,        0x39, (byte) 0xdb, (byte) 0xe1,        0x72,        0x09,        0x62,        0x3c,
    /* 10 */               0x3e,        0x7e,        0x5e, (byte) 0x8e, (byte) 0xf1, (byte) 0xa0, (byte) 0xcc, (byte) 0xa3,        0x2a,        0x1d, (byte) 0xfb, (byte) 0xb6, (byte) 0xd6,        0x20, (byte) 0xc4, (byte) 0x8d,
    /* 20 */        (byte) 0x81,        0x65, (byte) 0xf5, (byte) 0x89, (byte) 0xcb, (byte) 0x9d,        0x77, (byte) 0xc6,        0x57,        0x43,        0x56,        0x17, (byte) 0xd4,        0x40,        0x1a,        0x4d,
    /* 30 */        (byte) 0xc0,        0x63,        0x6c, (byte) 0xe3, (byte) 0xb7, (byte) 0xc8,        0x64,        0x6a,        0x53, (byte) 0xaa,        0x38, (byte) 0x98,        0x0c, (byte) 0xf4, (byte) 0x9b, (byte) 0xed,
    /* 40 */               0x7f,        0x22,        0x76, (byte) 0xaf, (byte) 0xdd,        0x3a,        0x0b,        0x58,        0x67, (byte) 0x88,        0x06, (byte) 0xc3,        0x35,        0x0d,        0x01, (byte) 0x8b,
    /* 50 */        (byte) 0x8c, (byte) 0xc2, (byte) 0xe6,        0x5f,        0x02,        0x24,        0x75, (byte) 0x93,        0x66,        0x1e, (byte) 0xe5, (byte) 0xe2,        0x54, (byte) 0xd8,        0x10, (byte) 0xce,
    /* 60 */               0x7a, (byte) 0xe8,        0x08,        0x2c,        0x12, (byte) 0x97,        0x32, (byte) 0xab, (byte) 0xb4,        0x27,        0x0a,        0x23, (byte) 0xdf, (byte) 0xef, (byte) 0xca, (byte) 0xd9,
    /* 70 */        (byte) 0xb8, (byte) 0xfa, (byte) 0xdc,        0x31,        0x6b, (byte) 0xd1, (byte) 0xad,        0x19,        0x49, (byte) 0xbd,        0x51, (byte) 0x96, (byte) 0xee, (byte) 0xe4, (byte) 0xa8,        0x41,
    /* 80 */        (byte) 0xda, (byte) 0xff, (byte) 0xcd,        0x55, (byte) 0x86,        0x36, (byte) 0xbe,        0x61,        0x52, (byte) 0xf8, (byte) 0xbb,        0x0e, (byte) 0x82,        0x48,        0x69, (byte) 0x9a,
    /* 90 */        (byte) 0xe0,        0x47, (byte) 0x9e,        0x5c,        0x04,        0x4b,        0x34,        0x15,        0x79,        0x26, (byte) 0xa7, (byte) 0xde,        0x29, (byte) 0xae, (byte) 0x92, (byte) 0xd7,
    /* A0 */        (byte) 0x84, (byte) 0xe9, (byte) 0xd2, (byte) 0xba,        0x5d, (byte) 0xf3, (byte) 0xc5, (byte) 0xb0, (byte) 0xbf, (byte) 0xa4,        0x3b,        0x71,        0x44,        0x46,        0x2b, (byte) 0xfc,
    /* B0 */        (byte) 0xeb,        0x6f, (byte) 0xd5, (byte) 0xf6,        0x14, (byte) 0xfe,        0x7c,        0x70,        0x5a,        0x7d, (byte) 0xfd,        0x2f,        0x18, (byte) 0x83,        0x16, (byte) 0xa5,
    /* C0 */        (byte) 0x91,        0x1f,        0x05, (byte) 0x95,        0x74, (byte) 0xa9, (byte) 0xc1,        0x5b,        0x4a, (byte) 0x85,        0x6d,        0x13,        0x07,        0x4f,        0x4e,        0x45,
    /* D0 */        (byte) 0xb2,        0x0f, (byte) 0xc9,        0x1c, (byte) 0xa6, (byte) 0xbc, (byte) 0xec,        0x73, (byte) 0x90,        0x7b, (byte) 0xcf,        0x59, (byte) 0x8f, (byte) 0xa1, (byte) 0xf9,        0x2d,
    /* E0 */        (byte) 0xf2, (byte) 0xb1,        0x00, (byte) 0x94,        0x37, (byte) 0x9f, (byte) 0xd0,        0x2e, (byte) 0x9c,        0x6e,        0x28,        0x3f, (byte) 0x80, (byte) 0xf0,        0x3d, (byte) 0xd3,
    /* F0 */               0x25, (byte) 0x8a, (byte) 0xb5, (byte) 0xe7,        0x42, (byte) 0xb3, (byte) 0xc7, (byte) 0xea, (byte) 0xf7,        0x4c,        0x11,        0x33,        0x03, (byte) 0xa2, (byte) 0xac,        0x60
    };
    //@formatter:on

    /**
     * Type 1 substitution layer
     */
    private byte[] SL1(byte[] array)
    {
        byte[] result = new byte[16];
        result[0] = SB1[unsigned(array[0])];
        result[1] = SB2[unsigned(array[1])];
        result[2] = SB3[unsigned(array[2])];
        result[3] = SB4[unsigned(array[3])];
        result[4] = SB1[unsigned(array[4])];
        result[5] = SB2[unsigned(array[5])];
        result[6] = SB3[unsigned(array[6])];
        result[7] = SB4[unsigned(array[7])];
        result[8] = SB1[unsigned(array[8])];
        result[9] = SB2[unsigned(array[9])];
        result[10] = SB3[unsigned(array[10])];
        result[11] = SB4[unsigned(array[11])];
        result[12] = SB1[unsigned(array[12])];
        result[13] = SB2[unsigned(array[13])];
        result[14] = SB3[unsigned(array[14])];
        result[15] = SB4[unsigned(array[15])];
        return result;
    }

    /**
     * Type 2 substitution layer
     */
    private byte[] SL2(byte[] array)
    {
        byte[] result = new byte[16];
        result[0] = SB3[unsigned(array[0])];
        result[1] = SB4[unsigned(array[1])];
        result[2] = SB1[unsigned(array[2])];
        result[3] = SB2[unsigned(array[3])];
        result[4] = SB3[unsigned(array[4])];
        result[5] = SB4[unsigned(array[5])];
        result[6] = SB1[unsigned(array[6])];
        result[7] = SB2[unsigned(array[7])];
        result[8] = SB3[unsigned(array[8])];
        result[9] = SB4[unsigned(array[9])];
        result[10] = SB1[unsigned(array[10])];
        result[11] = SB2[unsigned(array[11])];
        result[12] = SB3[unsigned(array[12])];
        result[13] = SB4[unsigned(array[13])];
        result[14] = SB1[unsigned(array[14])];
        result[15] = SB2[unsigned(array[15])];
        return result;
    }

   /*
    * 2.4.1.  Round Functions -----------------------------------------------------------------------------------------
    *
    *   There are two types of round functions for ARIA.  One is called an
    *   odd round function and is denoted by FO.  It takes as input a pair
    *   (D,RK) of two 128-bit strings and outputs
    *
    *   FO(D,RK) = A(SL1(D ^ RK)).
    *
    *   The other is called an even round function and is denoted by FE.  It
    *   takes as input a pair (D,RK) of two 128-bit strings and outputs
    *
    *   FE(D,RK) = A(SL2(D ^ RK)).
    *
    *   Functions SL1 and SL2, called substitution layers, are described in
    *   Section 2.4.2.  Function A, called a diffusion layer, is described in
    *   Section 2.4.3.
    * ------------------------------------------------------------------------------------------------------------------
    */
    /**
     * Odd round function
     */
    private byte[] FO(byte[] D, byte[] RK)
    {
        return A(SL1(XOR(D, RK)));
    }

    /**
     * Even round function
     */
    private byte[] FE(byte[] D, byte[] RK)
    {
        return A(SL2(XOR(D, RK)));
    }

    /*
     * 2.4.3.  Diffusion Layer -----------------------------------------------------------------------------------------
     *
     *    Diffusion layer A is an algorithm that takes a 16-byte string x0 ||
     *    x1 || ... || x15 as input and outputs a 16-byte string
     *    y0 || y1 ||...|| y15 by the following equations.
     *
     *       y0  = x3 ^ x4 ^ x6 ^ x8  ^ x9  ^ x13 ^ x14,
     *       y1  = x2 ^ x5 ^ x7 ^ x8  ^ x9  ^ x12 ^ x15,
     *       y2  = x1 ^ x4 ^ x6 ^ x10 ^ x11 ^ x12 ^ x15,
     *       y3  = x0 ^ x5 ^ x7 ^ x10 ^ x11 ^ x13 ^ x14,
     *       y4  = x0 ^ x2 ^ x5 ^ x8  ^ x11 ^ x14 ^ x15,
     *       y5  = x1 ^ x3 ^ x4 ^ x9  ^ x10 ^ x14 ^ x15,
     *       y6  = x0 ^ x2 ^ x7 ^ x9  ^ x10 ^ x12 ^ x13,
     *       y7  = x1 ^ x3 ^ x6 ^ x8  ^ x11 ^ x12 ^ x13,
     *       y8  = x0 ^ x1 ^ x4 ^ x7  ^ x10 ^ x13 ^ x15,
     *       y9  = x0 ^ x1 ^ x5 ^ x6  ^ x11 ^ x12 ^ x14,
     *       y10 = x2 ^ x3 ^ x5 ^ x6  ^ x8  ^ x13 ^ x15,
     *       y11 = x2 ^ x3 ^ x4 ^ x7  ^ x9  ^ x12 ^ x14,
     *       y12 = x1 ^ x2 ^ x6 ^ x7  ^ x9  ^ x11 ^ x12,
     *       y13 = x0 ^ x3 ^ x6 ^ x7  ^ x8  ^ x10 ^ x13,
     *       y14 = x0 ^ x3 ^ x4 ^ x5  ^ x9  ^ x11 ^ x14,
     *       y15 = x1 ^ x2 ^ x4 ^ x5  ^ x8  ^ x10 ^ x15.
     *
     *    Note that A is an involution.  That is, for any 16-byte input string
     *    x, x = A(A(x)) holds.
     * -----------------------------------------------------------------------------------------------------------------
     */
    private byte[] A(byte[] b)
    {
        int length = b.length;
        if (length != 16)
        {
            throw new IllegalArgumentException("Illegal input size. Diffusion layer should take 16-byte string as parameter.");
        }
        else
        {
            byte[] result = new byte[16];
            result[0] = (byte) (b[3] ^ b[4] ^ b[6] ^ b[8] ^ b[9] ^ b[13] ^ b[14]);
            result[1] = (byte) (b[2] ^ b[5] ^ b[7] ^ b[8] ^ b[9] ^ b[12] ^ b[15]);
            result[2] = (byte) (b[1] ^ b[4] ^ b[6] ^ b[10] ^ b[11] ^ b[12] ^ b[15]);
            result[3] = (byte) (b[0] ^ b[5] ^ b[7] ^ b[10] ^ b[11] ^ b[13] ^ b[14]);
            result[4] = (byte) (b[0] ^ b[2] ^ b[5] ^ b[8] ^ b[11] ^ b[14] ^ b[15]);
            result[5] = (byte) (b[1] ^ b[3] ^ b[4] ^ b[9] ^ b[10] ^ b[14] ^ b[15]);
            result[6] = (byte) (b[0] ^ b[2] ^ b[7] ^ b[9] ^ b[10] ^ b[12] ^ b[13]);
            result[7] = (byte) (b[1] ^ b[3] ^ b[6] ^ b[8] ^ b[11] ^ b[12] ^ b[13]);
            result[8] = (byte) (b[0] ^ b[1] ^ b[4] ^ b[7] ^ b[10] ^ b[13] ^ b[15]);
            result[9] = (byte) (b[0] ^ b[1] ^ b[5] ^ b[6] ^ b[11] ^ b[12] ^ b[14]);
            result[10] = (byte) (b[2] ^ b[3] ^ b[5] ^ b[6] ^ b[8] ^ b[13] ^ b[15]);
            result[11] = (byte) (b[2] ^ b[3] ^ b[4] ^ b[7] ^ b[9] ^ b[12] ^ b[14]);
            result[12] = (byte) (b[1] ^ b[2] ^ b[6] ^ b[7] ^ b[9] ^ b[11] ^ b[12]);
            result[13] = (byte) (b[0] ^ b[3] ^ b[6] ^ b[7] ^ b[8] ^ b[10] ^ b[13]);
            result[14] = (byte) (b[0] ^ b[3] ^ b[4] ^ b[5] ^ b[9] ^ b[11] ^ b[14]);
            result[15] = (byte) (b[1] ^ b[2] ^ b[4] ^ b[5] ^ b[8] ^ b[10] ^ b[15]);
            return result;
        }
    }

   /*
    * 2.2.  Key Scheduling Part ----------------------------------------------------------------------------------------
    *
    *    Let K denote a master key of 128, 192, or 256 bits.  Given the master
    *    key K, we first define 128-bit values KL and KR as follows.
    *
    *    KL || KR = K || 0 ... 0,
    *
    *    where the number of zeros is 128, 64, or 0, depending on the size of
    *    K.  That is, KL is set to the leftmost 128 bits of K and KR is set to
    *    the remaining bits of K (if any), right-padded with zeros to a
    *    128-bit value.  Then, we define four 128-bit values (W0, W1, W2, and
    *    W3) as the intermediate round values appearing in the encryption of
    *    KL || KR by a 3-round, 256-bit Feistel cipher.
    *
    *    W0 = KL,
    *    W1 = FO(W0, CK1) ^ KR,
    *    W2 = FE(W1, CK2) ^ W0,
    *    W3 = FO(W2, CK3) ^ W1.
    *
    *    Here, FO and FE, respectively called odd and even round functions,
    *    are defined in Section 2.4.1.  CK1, CK2, and CK3 are 128-bit
    *    constants, taking one of the following values.
    *
    *    C1 =  0x517cc1b727220a94fe13abe8fa9a6ee0
    *    C2 =  0x6db14acc9e21c820ff28b1d5ef5de2b0
    *    C3 =  0xdb92371d2126e9700324977504e8c90e
    *
    *    These values are obtained from the first 128*3 bits of the fractional
    *    part of 1/PI, where PI is the circle ratio.  Now the constants CK1,
    *    CK2, and CK3 are defined by the following table.
    *
    *        Key size  CK1  CK2  CK3
    *          128     C1   C2   C3
    *          192     C2   C3   C1
    *          256     C3   C1   C2
    *
    *    For example, if the key size is 192 bits, CK1 = C2, CK2 = C3, and
    *    CK3 = C1.
    *
    *    Once W0, W1, W2, and W3 are determined, we compute encryption round
    *    keys ek1, ..., ek17 as follows.
    *
    *    ek1  = W0 ^(W1 >>> 19),
    *    ek2  = W1 ^(W2 >>> 19),
    *    ek3  = W2 ^(W3 >>> 19),
    *    ek4  = (W0 >>> 19) ^ W3,
    *    ek5  = W0 ^ (W1 >>> 31),
    *    ek6  = W1 ^ (W2 >>> 31),
    *    ek7  = W2 ^ (W3 >>> 31),
    *    ek8  = (W0 >>> 31) ^ W3,
    *    ek9  = W0 ^ (W1 <<< 61),
    *    ek10 = W1 ^ (W2 <<< 61),
    *    ek11 = W2 ^ (W3 <<< 61),
    *    ek12 = (W0 <<< 61) ^ W3,
    *    ek13 = W0 ^ (W1 <<< 31),
    *    ek14 = W1 ^ (W2 <<< 31),
    *    ek15 = W2 ^ (W3 <<< 31),
    *    ek16 = (W0 <<< 31) ^ W3,
    *    ek17 = W0 ^ (W1 <<< 19).
    *
    *    The number of rounds depends on the size of the master key as
    *    follows.
    *
    *         Key size     Number of Rounds
    *          128              12
    *          192              14
    *          256              16
    *
    *    Due to an extra key addition layer in the last round, 12-, 14-, and
    *    16-round algorithms require 13, 15, and 17 round keys, respectively.
    *
    *    Decryption round keys are derived from the encryption round keys.
    *
    *    dk1 = ek{n+1},
    *    dk2 = A(ek{n}),
    *    dk3 = A(ek{n-1}),
    *    ...,
    *    dk{n}= A(ek2),
    *    dk{n+1}= ek1.
    *
    *    Here, A and n denote the diffusion layer of ARIA and the number of
    *    rounds, respectively.  The diffusion layer A is defined in Section
    *    2.4.3.
    * ------------------------------------------------------------------------------------------------------------------
    */
    private void scheduleKey(byte[] key)
    {
        mKeyLength = key.length;
        final byte[] CK1;
        final byte[] CK2;
        final byte[] CK3;

        //128-bit master key?
        if (mKeyLength == 16)
        {
            CK1 = C1;
            CK2 = C2;
            CK3 = C3;
            mNumberRounds = 12;
        }
        //192-bit master key?
        else if (mKeyLength == 24)
        {
            CK1 = C2;
            CK2 = C3;
            CK3 = C1;
            mNumberRounds = 14;
        }
        //256-bit master key?
        else if (mKeyLength == 32)
        {
            CK1 = C3;
            CK2 = C1;
            CK3 = C2;
            mNumberRounds = 16;
        }
        else
        {
            throw new IllegalArgumentException("Illegal key length. Only 128, 192 and 256 bit keys are valid.");
        }

        //Compute 128-bit KL value (also W0). KL is set to the leftmost 128 bits of Key.
        byte[] W0 = Arrays.copyOf(key, 16);
        //KR is set to the remaining bits of K (if any), right-padded with zeros to a 128-bit value.
        byte[] KR = (mKeyLength > 16) ? Arrays.copyOfRange(key, 16, 31) : new byte[16];

        //Compute intermediate values W0, W1, W2, and W3
        byte[] W1 = XOR(FO(W0, CK1), KR);
        byte[] W2 = XOR(FE(W1, CK2), W0);
        byte[] W3 = XOR(FO(W2, CK3), W1);

        //Compute encryption round keys
        mEK = new byte[17][];
        mEK[0] = XOR(W0, ROR(W1, 19));
        mEK[1] = XOR(W1, ROR(W2, 19));
        mEK[2] = XOR(W2, ROR(W3, 19));
        mEK[3] = XOR(ROR(W0, 19), W3);
        mEK[4] = XOR(W0, ROR(W1, 31));
        mEK[5] = XOR(W1, ROR(W2, 31));
        mEK[6] = XOR(W2, ROR(W3, 31));
        mEK[7] = XOR(ROR(W0, 31), W3);
        mEK[8] = XOR(W0, ROL(W1, 61));
        mEK[9] = XOR(W1, ROL(W2, 61));
        mEK[10] = XOR(W2, ROL(W3, 61));
        mEK[11] = XOR(ROL(W0, 61), W3);
        mEK[12] = XOR(W0, ROL(W1, 31));
        mEK[13] = XOR(W1, ROL(W2, 31));
        mEK[14] = XOR(W2, ROL(W3, 31));
        mEK[15] = XOR(ROL(W0, 31), W3);
        mEK[16] = XOR(W0, ROL(W1, 19));

        //Compute decryption round keys from the encryption round keys
        mDK = new byte[mNumberRounds + 1][];
        mDK[0] = mEK[mNumberRounds];
        for (int i = 1; i < mNumberRounds; i++)
            mDK[i] = A(mEK[mNumberRounds - i]);
        mDK[mNumberRounds] = mEK[0];
    }

   /*
    * 2.3.1.  Encryption Process ---------------------------------------------------------------------------------------
    *
    * 2.3.1.1.  Encryption for 128-Bit Keys
    *
    *    Let P be a 128-bit plaintext and K be a 128-bit master key.  Let ek1,
    *    ..., ek13 be the encryption round keys defined by K.  Then the
    *    ciphertext C is computed by the following algorithm.
    *
    *    P1  = FO(P  , ek1 );              // Round 1
    *    P2  = FE(P1 , ek2 );              // Round 2
    *    P3  = FO(P2 , ek3 );              // Round 3
    *    P4  = FE(P3 , ek4 );              // Round 4
    *    P5  = FO(P4 , ek5 );              // Round 5
    *    P6  = FE(P5 , ek6 );              // Round 6
    *    P7  = FO(P6 , ek7 );              // Round 7
    *    P8  = FE(P7 , ek8 );              // Round 8
    *    P9  = FO(P8 , ek9 );              // Round 9
    *    P10 = FE(P9 , ek10);              // Round 10
    *    P11 = FO(P10, ek11);              // Round 11
    *    C   = SL2(P11 ^ ek12) ^ ek13;     // Round 12
    *
    * 2.3.1.2.  Encryption for 192-Bit Keys
    *
    *    Let P be a 128-bit plaintext and K be a 192-bit master key.  Let ek1,
    *    ..., ek15 be the encryption round keys defined by K.  Then the
    *    ciphertext C is computed by the following algorithm.
    *
    *    P1  = FO(P  , ek1 );              // Round 1
    *    P2  = FE(P1 , ek2 );              // Round 2
    *    P3  = FO(P2 , ek3 );              // Round 3
    *    P4  = FE(P3 , ek4 );              // Round 4
    *    P5  = FO(P4 , ek5 );              // Round 5
    *    P6  = FE(P5 , ek6 );              // Round 6
    *    P7  = FO(P6 , ek7 );              // Round 7
    *    P8  = FE(P7 , ek8 );              // Round 8
    *    P9  = FO(P8 , ek9 );              // Round 9
    *    P10 = FE(P9 , ek10);              // Round 10
    *    P11 = FO(P10, ek11);              // Round 11
    *    P12 = FE(P11, ek12);              // Round 12
    *    P13 = FO(P12, ek13);              // Round 13
    *    C   = SL2(P13 ^ ek14) ^ ek15;     // Round 14
    *
    * 2.3.1.3.  Encryption for 256-Bit Keys
    *
    *    Let P be a 128-bit plaintext and K be a 256-bit master key.  Let ek1,
    *    ..., ek17 be the encryption round keys defined by K.  Then the
    *    ciphertext C is computed by the following algorithm.
    *
    *    P1 = FO(P  , ek1 );              // Round 1
    *    P2 = FE(P1 , ek2 );              // Round 2
    *    P3 = FO(P2 , ek3 );              // Round 3
    *    P4 = FE(P3 , ek4 );              // Round 4
    *    P5 = FO(P4 , ek5 );              // Round 5
    *    P6 = FE(P5 , ek6 );              // Round 6
    *    P7 = FO(P6 , ek7 );              // Round 7
    *    P8 = FE(P7 , ek8 );              // Round 8
    *    P9 = FO(P8 , ek9 );              // Round 9
    *    P10= FE(P9 , ek10);              // Round 10
    *    P11= FO(P10, ek11);              // Round 11
    *    P12= FE(P11, ek12);              // Round 12
    *    P13= FO(P12, ek13);              // Round 13
    *    P14= FE(P13, ek14);              // Round 14
    *    P15= FO(P14, ek15);              // Round 15
    *    C  = SL2(P15 ^ ek16) ^ ek17;     // Round 16
    * ------------------------------------------------------------------------------------------------------------------
    */
    public byte[] encrypt(byte[] plainText)
    {
        return crypt(plainText, mEK);
    }

    private byte[] crypt(byte[] text, byte[][] keys)
    {
        int length = text.length;
        if (length % mKeyLength != 0)
        {
            throw new IllegalArgumentException("Text length must be a multiple of key length. Current key length is " +
                    String.valueOf(mKeyLength) + " bytes.");
        }
        else
        {
            byte[] result = new byte[length];
            byte[] block = new byte[mKeyLength];
            int nBlocks = length / mKeyLength;
            for (int i = 0; i < nBlocks; i++)
            {
                int currentPos = i * mKeyLength;
                System.arraycopy(text, currentPos, block, 0, mKeyLength);
                block = FO(block, keys[0]);
                for (int j = 1; j < mNumberRounds - 1; j++)
                    block = (j % 2) == 0 ? FO(block, keys[j]) : FE(block, keys[j]);
                block = XOR(SL2(XOR(block, keys[mNumberRounds - 1])), keys[mNumberRounds]);
                System.arraycopy(block, 0, result, currentPos, mKeyLength);
            }
            return result;
        }
    }

   /*
    * 2.3.2.  Decryption Process ---------------------------------------------------------------------------------------
    *
    *   The decryption process of ARIA is the same as the encryption process
    *   except that encryption round keys are replaced by decryption round
    *   keys.  For example, encryption round keys ek1, ..., ek13 of the
    *   12-round ARIA algorithm are replaced by decryption round keys dk1,
    *   ..., dk13, respectively.
    * ------------------------------------------------------------------------------------------------------------------
    */
    public byte[] decrypt(byte[] cipherText)
    {
        return crypt(cipherText, mDK);
    }

    public AriaCipher(byte[] key)
    {
        scheduleKey(key);
    }

   // Utility functions ------------------------------------------------------------------------------------------------

    /**
     * XOR each byte from first array with corresponding byte from second. If second array size less than first, than
     * elements past this size from first array won't be XOR'ed at all.
     */
    public static byte[] XOR(byte[] x, byte[] y)
    {
        int length = x.length;
        byte[] result = new byte[length];
        System.arraycopy(x, 0, result, 0, length);
        int i = 0;
        while (i < length && i < y.length)
        {
            result[i] ^= y[i];
            i++;
        }
        return result;
    }

    /**
     * Circular rotate byte array LEFT by specified amount of bits.
     *
     * @param array  array to be rotated.
     * @param nShift amount of bits to be rotated.
     * @return NEW array circular rotated left by specified amount of bits.
     */
    public static byte[] ROL(byte[] array, int nShift)
    {
        int nBytes = array.length;
        byte[] result = new byte[nBytes];
        nShift = nShift % (nBytes * 8);
        if (nShift == 0)
        {
            System.arraycopy(array, 0, result, 0, nBytes);
        }
        else
        {
            int byteOffset = nShift / 8;
            int leftShift = nShift % 8;
            int rightShift = 8 - leftShift;
            for (int i = 0; i < nBytes; i++)
            {
                byte leftPart = (byte) (array[(i + byteOffset) % nBytes] << leftShift);
                byte rightPart = (byte) (unsigned(array[(i + byteOffset + 1) % nBytes]) >> rightShift);
                result[i] = (byte) (leftPart | rightPart);
            }
        }
        return result;
    }

    /**
     * Circular rotate byte array RIGHT by specified amount of bits.
     *
     * @param array  array to be rotated.
     * @param nShift amount of bits to be rotated.
     * @return NEW array circular rotated right by specified amount of bits.
     */
    public static byte[] ROR(byte[] array, int nShift)
    {
        return ROL(array, (array.length * 8) - nShift);
    }

    public static int unsigned(byte b)
    {
        return b & 0xff;
    }
}
