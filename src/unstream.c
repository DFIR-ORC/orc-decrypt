//
// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Copyright © 2011-2020 ANSSI. All Rights Reserved.
//
// Author(s): Yoann Guillot (ANSSI)
//
/*
 * transforme les fichiers de sortie ORC au format 'stream/journal' en un fichier standard (7z)
 *
 * Usage:
 *   orc-unstream <input stream> <output file>
 *   ex: ./orc-unstream ORC_Foo_Quick.7zs ORC_Foo_Quick.7z
 */
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#if defined(_MSC_VER)
#include <sys/types.h>
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;

#include <fcntl.h>
#include <io.h>
#endif

//#define DEBUG

static const uint32_t VERSION_JRNL = 2;
static const char MAGIC_JRNL[4]  = { 'J', 'R', 'N', 'L' };
static const char MAGIC_WRITE[4] = { 'W', 'R', 'I', 'T' };
static const char MAGIC_SEEK[4]  = { 'S', 'E', 'E', 'K' };
static const char MAGIC_CLOSE[4] = { 'C', 'L', 'O', 'S' };

typedef struct {
	char magic[4];
	uint32_t version;
} t_jrnl;


typedef struct {
	char magic[4];
	uint32_t dw;
	uint64_t ull;
} t_op;


// reads stream data from fd_in, writes unstreamed data to fd_out
// exit() on errors
int do_unstream( FILE *f_in, FILE *f_out )
{
	t_jrnl jrnl;
	int ret;

	ret = fread( &jrnl, 1, sizeof(t_jrnl), f_in );

	if ( ret < 0 )
	{
		perror( "Unstream: cannot read stream signature" );
		return EXIT_FAILURE;
	}

	if ( ret != sizeof(t_jrnl) ||  *jrnl.magic != *MAGIC_JRNL )
	{
		fprintf( stderr, "Unstream: not a stream file, bad magic\n" );
		return EXIT_FAILURE;
	}

	if ( jrnl.version != VERSION_JRNL )
	{
		fprintf( stderr, "Unstream: unhandled JRNL version (%x, but I know only %x)\n", (unsigned)jrnl.version, (unsigned)VERSION_JRNL );
		return EXIT_FAILURE;
	}

	for (;;) {
		t_op op;

#ifdef DEBUG
fprintf( stderr, "Unstream: reading stream op at %llx\n", (unsigned long long)ftell( f_in ) );
#endif
		ret = fread( &op, 1, sizeof(op), f_in );
		if ( ret != sizeof(op) )
		{
			if ( ret == -1 )
				fprintf( stderr, "Unstream: cannot read stream opcode: %m\n" );
			else
				fprintf( stderr, "Unstream: cannot read stream opcode\n" );
			return EXIT_FAILURE;
		}

		if ( *op.magic == *MAGIC_CLOSE )
		{
#ifdef DEBUG
fprintf( stderr, "CLOSE\n" );
#endif
			break;
		}
		else if ( *op.magic == *MAGIC_SEEK )
		{
			off_t off = op.ull;

			int meth = SEEK_SET;
			if ( op.dw == 1 )
				meth = SEEK_CUR;
			else if ( op.dw == 2 )
				meth = SEEK_END;

#ifdef DEBUG
fprintf( stderr, "SEEK %llx %d\n", (unsigned long long)off, meth );
#endif
			fseek( f_out, off, meth );

		}
		else if ( *op.magic == *MAGIC_WRITE )
		{
#define BUFSZ (1024*1024)
			static char buf[ BUFSZ ];
			uint64_t len = op.ull;

#ifdef DEBUG
fprintf( stderr, "WRIT %llx\n", (unsigned long long)len );
#endif
			while ( len > 0 )
			{
				ssize_t chunk_len = fread( buf, 1, (len > BUFSZ ? BUFSZ : len), f_in );
				if ( chunk_len <= 0 )
				{
					if ( chunk_len < 0 )
						fprintf( stderr, "Unstream: cannot read data: %m\n" );
					else
						fprintf( stderr, "Unstream: cannot read data\n" );
					return EXIT_FAILURE;
				}

				ret = fwrite( buf, 1, chunk_len, f_out );
				if ( ret != chunk_len )
				{
					if ( ret == -1 )
						fprintf( stderr, "Unstream: cannot write data: %m\n" );
					else
						fprintf( stderr, "Unstream: cannot write data\n" );
					return EXIT_FAILURE;
				}

				len -= chunk_len;
			}
		}
		else
		{
			fprintf( stderr, "Unstream: bad stream opcode\n" );
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}


int main( int argc, char **argv )
{
	if ( argc < 3 )
	{
		fprintf( stderr, "Usage: orc-untream <in_orc_stream.7zs> <out_orc_unstream.7z>\n" );
		exit(EXIT_FAILURE);
	}

	FILE *f_in = NULL;
	if ( !strcmp( argv[1], "-" ) )
	{
#if defined(_MSC_VER)
        _setmode(_fileno(stdin), _O_BINARY);
#endif
		f_in = stdin;
	} else {
		f_in = fopen( argv[1], "rb" );
	}
	if ( !f_in )
	{
		perror( "Unstream: open in" );
		exit(EXIT_FAILURE);
	}

	FILE *f_out = fopen( argv[2], "wbx" );
	if ( !f_out )
	{
		perror( "Unstream: open out" );
		exit(EXIT_FAILURE);
	}

	int ret = do_unstream( f_in, f_out );

	if ( fclose( f_out ) == -1 )
	{
		perror( "Unstream: close out" );
		exit(EXIT_FAILURE);
	}
	fclose( f_in );

	return ret;
}
