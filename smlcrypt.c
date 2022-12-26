#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include <openssl/sha.h>	// SHA1
#include <openssl/evp.h>	// EVP*
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <getopt.h>

typedef struct __attribute__ ((__packed__)) fw_header { // non-aligned structure!
    char	vendor[0x20];		// SmartLabs
    char	device[0x20];		// ps7105
    uint16_t	ver_major;		// 5
    uint16_t	ver_minor;		// 23850
    uint32_t	ver_build;		// 190121
    uint32_t	old_crc;		// 0 on new firmwares
    uint32_t	timestamp;		// unixtime
    uint16_t	unknown2;		// 00 03
    uint16_t	sigblock_size;		// signature block size/offset (0 - unsigned, 03 24 / 02 24)
    uint32_t	hw_rev;			// 1
    uint16_t	sigblock_offset;	// 03 1C / 02 1C - signature block size/offset from current position to begginning of next unit
    uint16_t	unknown4;		// 0
} fw_header_t;
// next is uint16_t signature size + signature payload
// after all signatures data sha1sum is placed

typedef struct __attribute__ ((__packed__)) unit_header { // non-aligned structure!
    uint32_t	size;			// payload_size + 4
    uint16_t	hdr_size;		// 03 22
    uint8_t	image_type;		// 1:U-Boot Image, 2:Linux Kernel Image, 3:Root FS Image, 4:Setup Script Image, 5:Branding Image, 6:Backup Linux Kernel Image, 7:Post-download Script, 8:Infomir Mag250 Logo
    uint8_t	unknown1;		// 0
    uint32_t	crc;			// ntohl(apple_crc)
} unit_header_t;
// next is uint16_t signature size + signature payload
// after all signatures data sha1sum is placed

// global: unit ofset for parsing next block

int unit_offset = 0;

void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

void hexdump_nonempty(char *name, void *ptr, int size, uint8_t emptychar) {
    void *emptyarray = malloc(size);
    memset(emptyarray, emptychar, size);
    if (memcmp(emptyarray, ptr, size)) {
	hexDump(name, ptr, size);
    } else {
	printf("%s is empty! (0x%02x)\n", name, emptychar);
    }
    free (emptyarray);
}

/* реализация crc32 из openssh */
static const uint32_t crc32tab[] = {
        0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL,
        0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
        0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L,
        0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
        0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
        0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
        0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL,
        0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
        0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L,
        0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
        0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L,
        0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
        0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L,
        0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
        0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
        0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
        0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL,
        0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
        0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L,
        0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
        0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL,
        0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
        0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL,
        0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
        0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
        0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
        0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L,
        0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
        0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L,
        0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
        0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L,
        0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
        0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL,
        0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
        0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
        0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
        0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL,
        0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
        0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL,
        0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
        0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L,
        0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
        0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L,
        0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
        0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
        0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
        0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L,
        0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
        0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL,
        0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
        0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L,
        0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
        0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL,
        0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
        0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
        0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
        0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L,
        0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
        0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L,
        0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
        0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L,
        0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
        0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L,
        0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL
};

uint32_t ssh_crc32(const uint8_t *buf, uint32_t size, uint32_t crc)
{
        uint32_t i;

        for (i = 0;  i < size;  i++)
                crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
        return crc;
}

int verify_fw_header(unsigned char *src_mem, int size_limit, X509* key)
{
    unsigned char sha1sum[20], calc_sha1sum[20];
    uint16_t next_signature_size = 0; // uint16_t to use ntohs() function

    fw_header_t fw_header;

    int retcode = 0, sigmatch = 0, current_pointer = 0;

    memcpy(&fw_header, src_mem, sizeof(fw_header));

    printf("> smartlabs firmware common\n");

    printf(">> vendor id       : %s\n", (char *)&fw_header.vendor);
    printf(">> device id       : %s\n", (char *)&fw_header.device);

    printf(">> hardware version: %u\n", ntohl(fw_header.hw_rev));

    printf(">> major version   : %u\n", ntohs(fw_header.ver_major));
    printf(">> minor version   : %u\n", ntohs(fw_header.ver_minor));
    printf(">> build version   : %u\n", ntohl(fw_header.ver_build));

    printf(">> payload old.CRC : %#x\n", fw_header.old_crc);

    time_t timestamp = ntohl(fw_header.timestamp);
    printf(">> timestamp       : %u, %s", (unsigned int)timestamp, ctime(&timestamp));
    printf(">> signature block : %u\n", ntohs(fw_header.sigblock_size));

    if (ntohs(fw_header.sigblock_size) < 6){
	printf(">> Firmware without signature block, payload starts at offset 0x%x\n", (char *)&fw_header.sigblock_offset - (char *)&fw_header);
	unit_offset += (char *)&fw_header.sigblock_offset - (char *)&fw_header;
	return 0;
    }
    printf(">> signature offset: %u\n", ntohs(fw_header.sigblock_offset));

    current_pointer += sizeof(fw_header);

    int hdrskip = sizeof(fw_header) + ntohs(fw_header.sigblock_offset);

    while (current_pointer < size_limit) {

        memcpy(&next_signature_size, src_mem + current_pointer, sizeof(next_signature_size));
	next_signature_size = ntohs(next_signature_size);

	current_pointer += sizeof(next_signature_size);
	printf(">>> read signature size:  %d\n", next_signature_size);

	if (next_signature_size != 256) break;

#ifdef DEBUG
	printf(">>> current pointer : %u, 0x%x\n", current_pointer, current_pointer);
//	hexDump (">>>> read signature", src_mem + current_pointer, next_signature_size);
#endif

	if (key) {

    	    EVP_PKEY* pPubkey = X509_get_pubkey(key);
    	    EVP_MD_CTX* ctx = EVP_MD_CTX_create();

    	    if (!EVP_DigestVerifyInit(ctx, NULL, EVP_sha1(), NULL, pPubkey))					goto err_EVP_XTX_destroy;
    	    if (!EVP_DigestVerifyUpdate(ctx, src_mem, sizeof(fw_header)))					goto err_EVP_XTX_destroy;
    	    if (!EVP_DigestVerifyUpdate(ctx, src_mem + hdrskip, size_limit - hdrskip))				goto err_EVP_XTX_destroy;
    	    if (!EVP_DigestVerifyFinal(ctx,(unsigned char*) src_mem + current_pointer, next_signature_size))	goto err_EVP_XTX_destroy_final;

	    printf(">>>> Public key matches payload signature!\n");
	    sigmatch++;
	    goto err_EVP_XTX_destroy_final;

	    err_EVP_XTX_destroy:;
#ifdef DEBUG
	    int openssl_error = ERR_get_error();
	    fprintf(stderr, "%s\nUse \"openssl errstr 0x%0X\" to describe code\n", ERR_error_string(openssl_error, NULL), openssl_error);
#endif
	    err_EVP_XTX_destroy_final:
    	    EVP_MD_CTX_destroy(ctx);
	}
	current_pointer += next_signature_size;
    }

    if (next_signature_size != 0) {
	fprintf(stderr, "!!! Cannot detect signature end, bad signature length.\n");
	return 1;
    }

    memcpy(&sha1sum, src_mem + current_pointer, sizeof(sha1sum));
    current_pointer += sizeof(sha1sum);

#ifdef DEBUG
        printf(">> SHA1 start: 0, SHA1 end: %d\n", sizeof(fw_header));
        printf(">> SHA1 start: %d, SHA1 end: %d\n", hdrskip, size_limit);
#endif

    SHA_CTX context;

    SHA1_Init(&context);
    SHA1_Update(&context, src_mem, sizeof(fw_header)); 		    // header
    SHA1_Update(&context, src_mem + hdrskip, size_limit - hdrskip); // after header + signature to end
    SHA1_Final(calc_sha1sum, &context);

    if (memcmp(&sha1sum, &calc_sha1sum, sizeof(calc_sha1sum))) {
	fprintf(stderr, "!!! calculate payload SHA1 error\n");
#ifdef DEBUG
	hexDump (">> calculated sha1sum", &calc_sha1sum, sizeof(calc_sha1sum));
	hexDump (">> read sha1sum", &sha1sum, sizeof(sha1sum));

	printf(">> current pointer : %u, 0x%x\n", current_pointer, current_pointer);
#endif
	retcode++;
    } else {
        printf(">> payload SHA1 check OK!\n");
    }

    if (key && !sigmatch) {
	fprintf(stderr, "!!! Public key specified, but no signature matches it!\n");
	retcode++;
    }

    if (!retcode) { unit_offset += hdrskip; } // move to payload
    return retcode;
}

int verify_unit_header(unsigned char *src_mem, int size_limit, int opt_dump, X509* key)
{
    uint32_t calc_crc;
    unsigned char sha1sum[20], calc_sha1sum[20];
    uint16_t next_signature_size = 0; // uint16_t to use ntohs() function

    unit_header_t unit_header;

    int retcode = 0, sigmatch = 0, current_pointer = 0, payload_size = 0;

    memcpy(&unit_header, src_mem, sizeof(unit_header));

    printf("> smartlabs firmware unit\n");

    printf(">> unit size       : %u, 0x%x\n", ntohl(unit_header.size), ntohl(unit_header.size));
    printf(">> header size     : %u, 0x%x\n", ntohs(unit_header.hdr_size), ntohs(unit_header.hdr_size));

    printf(">> image type      : %u\n", unit_header.image_type);
    printf(">> unknown1 field  : %u\n", unit_header.unknown1);
    printf(">> payload CRC     : %#x\n", unit_header.crc);

    payload_size = ntohl(unit_header.size) - ntohs(unit_header.hdr_size) - 2;
    printf(">> calculated payload size  : %u\n", payload_size);

    current_pointer += sizeof(unit_header);

    while (current_pointer < size_limit) {

        memcpy(&next_signature_size, src_mem + current_pointer, sizeof(next_signature_size));
	next_signature_size = ntohs(next_signature_size);

	current_pointer += sizeof(next_signature_size);
	printf(">>> read signature size:  %d\n", next_signature_size);

	if (next_signature_size != 256) break;

#ifdef DEBUG
	printf(">> local pointer : %u, 0x%x\n", current_pointer, current_pointer);
//	hexDump (">>> read signature", src_mem + current_pointer, next_signature_size);
#endif

	if (key) {

    	    EVP_PKEY* pPubkey = X509_get_pubkey(key);
    	    EVP_MD_CTX* ctx = EVP_MD_CTX_create();

    	    if (!EVP_DigestVerifyInit(ctx, NULL, EVP_sha1(), NULL, pPubkey))					goto err_EVP_XTX_destroy;
    	    if (!EVP_DigestVerifyUpdate(ctx, src_mem + ntohs(unit_header.hdr_size) + 6, payload_size))		goto err_EVP_XTX_destroy;
    	    if (!EVP_DigestVerifyFinal(ctx, (unsigned char*) src_mem + current_pointer, next_signature_size))	goto err_EVP_XTX_destroy_final;

	    printf(">>> Public key matches payload signature!\n");
	    sigmatch++;
	    goto err_EVP_XTX_destroy_final;

	    err_EVP_XTX_destroy:;
#ifdef DEBUG
	    int openssl_error = ERR_get_error();
	    fprintf(stderr, "%s\nUse \"openssl errstr 0x%0X\" to describe code\n", ERR_error_string(openssl_error, NULL), openssl_error);
#endif
	    err_EVP_XTX_destroy_final:
    	    EVP_MD_CTX_destroy(ctx);
	}

	current_pointer += next_signature_size;

    }

    if (next_signature_size != 0) {
	fprintf(stderr, "!!! Cannot detect signature end, bad signature length.\n");
	return 1;
    }

    memcpy(&sha1sum, src_mem + current_pointer, sizeof(sha1sum));
    current_pointer += sizeof(sha1sum);

#ifdef DEBUG
	printf(">> local pointer : %u, 0x%x\n", current_pointer, current_pointer);
#endif
    calc_crc = htonl(~ssh_crc32(src_mem + ntohs(unit_header.hdr_size) + 6, payload_size, 0xFFFFFFFF)); // apple CRC32

    if (calc_crc != unit_header.crc) {
	fprintf(stderr, "!!! calculate payload CRC error: calculated %#08x, read %#08x\n", calc_crc, unit_header.crc);
	retcode++;
    } else {
        printf(">> payload CRC check OK!\n");
    }

    SHA_CTX context;

    SHA1_Init(&context);
    SHA1_Update(&context, src_mem + ntohs(unit_header.hdr_size) + 6, payload_size); // whole payload
    SHA1_Final(calc_sha1sum, &context);

    if (memcmp(&sha1sum, &calc_sha1sum, sizeof(calc_sha1sum))) {
	fprintf(stderr, "!!! calculate payload SHA1 error\n");
#ifdef DEBUG
	hexDump (">> calculated sha1sum", &calc_sha1sum, sizeof(calc_sha1sum));
	hexDump (">> read sha1sum", &sha1sum, sizeof(sha1sum));
#endif
	retcode ++;
    } else {
        printf(">> payload SHA1 check OK!\n");
    }

    if (!retcode && opt_dump) {
	    char output_name[64];
	    sprintf(output_name, "unit_%d_%d.bin", unit_header.image_type, unit_offset);

            FILE* target_file = fopen(output_name,"w");
            if (target_file == 0) {
                perror("Cannot open file for write");
                free(src_mem);
                return 1;
            }
            
            fseek(target_file, 0, SEEK_SET);
            fwrite(src_mem + current_pointer, payload_size, 1, target_file);
            fclose(target_file);
    }

    current_pointer += payload_size;
#ifdef DEBUG
	printf(">> local pointer : %u, 0x%x (unit end)\n", current_pointer, current_pointer);
#endif

    if (unit_offset > 0 && !retcode) {
	unit_offset += current_pointer; // move to next unit
    } else {
	unit_offset = -1; // no more units
    }

    if (key && !sigmatch) {
	fprintf(stderr, "!!! Public key specified, but no signature matches it!\n");
	retcode++;
    }

    unit_offset += unit_offset % 4; // align to 4-byte boundary

    return retcode;
}

int main(int argc, char ** argv)
{

 int opt_input = 0, opt_output = 0, opt_verify = 0, opt_edit = 0, opt_dump = 0;
 int retcode = 0;
 char *input_name = NULL, *output_name = NULL, *pkey_name = NULL;
 X509* oCertificate=NULL;

 static char options_exist[] = "vdi:o:k:p:"; // common options set for both getopt()

 int c;
 while ( 1 ) {
        c = getopt(argc, argv, options_exist);
        if (c == -1)
                break;

        switch (c) {
                case 'v':  // verify nvram
                        opt_verify++;
                        break;
                case 'd':  // verify and dump units from nvram
                        opt_dump++;
                        break;
                case 'e':  // edit nvram
                        opt_edit++;
                        break;
                case 'i':  // input file
                        input_name = optarg;
                        opt_input++;
                        break;
                case 'o':  // output_file
                        output_name = optarg;
                        opt_output++;
                        break;
                case 'k':  // public key
                        pkey_name = optarg;

			FILE *lFp=NULL;
			lFp=fopen(pkey_name,"rb");

			if (lFp == NULL) {
			    perror("Cannot open X509 certificate file for read");
			    retcode++;
			    goto exit_nofree;
			}

			oCertificate = PEM_read_X509(lFp, NULL, NULL, NULL);
			if (oCertificate  == NULL )
			{
				//Certificate may be DER encode 
				oCertificate = d2i_X509_fp(lFp, NULL);
			}
			fclose(lFp);

			if (oCertificate == NULL) {
			    fprintf(stderr, "Unable to parse X509 certificate from %s\n", pkey_name);
			    retcode++;
			    goto exit_nofree;
			}

                        break;
                case 'p':  // file position
                        if (!sscanf(optarg, "0x%8x", &unit_offset)) goto print_usage;
                        break;
                default:
                        goto print_usage;
                }
 }

    if (!opt_input)				goto print_usage;

//    if (opt_verify && opt_edit)			goto print_usage;

    if (opt_verify && !opt_input)		goto print_usage;
//    if (opt_edit && !(opt_input && opt_output))	goto print_usage;

    size_t input_size;


    FILE* source_file = fopen(input_name,"r");
    if (source_file == 0) {
        perror("Cannot open file for read");
        return 1;
    }

    /* будет ли fstat тут более хорош? */
    fseek(source_file, 0, SEEK_END);
    input_size = ftell(source_file);

    unsigned char *src_mem = malloc(input_size);
    memset(src_mem, 0, input_size);

    fseek(source_file, 0, SEEK_SET);
    fread(src_mem, input_size, 1, source_file);
    fclose(source_file);


    if (opt_verify) {
        retcode += verify_fw_header(src_mem + unit_offset, input_size - unit_offset, oCertificate);
	while (unit_offset > 0 && unit_offset < input_size && !retcode) {
    	    printf("> UNIT parsing start (global): %u, 0x%x\n", unit_offset, unit_offset);
    	    retcode += verify_unit_header(src_mem + unit_offset, input_size - unit_offset, opt_dump, oCertificate);
	    if (retcode) unit_offset = -1;
	}

    }
    free(src_mem);

    exit_nofree:
    if (retcode) fprintf(stderr, "Some errors happen.\n");
    return retcode;

    print_usage:

    fprintf(stderr, "Usage for %s:\n"
    " -v     verify firmware\n"
    " -i     <input file>\n"
    " -d     <dump contents>\n"
    " -k     <public key for signature check> (in ASN.1 DER format)\n"
    "\n (C) [anp/hsw] 2019, GPLv2 license applied\n"
    " crc32 code (C) openssh team\n"
    "\n", argv[0]);

    return 1;
}

