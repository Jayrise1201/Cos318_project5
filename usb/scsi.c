#include "../util.h"
#include "../thread.h"
#include "scsi.h"
#include "allocator.h"
#include "debug.h"
#include "error.h"

DEBUG_NAME("SCSI");

/* 
 * For purpose of this OS we assume there is only 
 * one SCSI device which is a USB flash drive 
 */
static struct scsi_dev *scsi = NULL;
static int scsi_read_write(int dir, int block_start,
                           int block_count, char *data);
static int scsi_read_capacity();

int scsi_init(struct scsi_ifc *ifc) {
  int rc;
  scsi = kzalloc(sizeof(struct scsi_dev));
  if (scsi == NULL)
    return ERR_NO_MEM;

  /* Copy the driver interface */
  scsi->driver = ifc->driver;
  scsi->read = ifc->read;
  scsi->write = ifc->write;
  spinlock_init(&scsi->lock);

  rc = scsi_read_capacity();
  DEBUG("Reading device capacity parameters %s", DEBUG_STATUS(rc));

  if(rc < 0) {
    kfree(scsi);
    return -1;
  }

  DEBUG("Device block size %d, block count %d", 
      scsi->block_size, scsi->total_block_count);

  scsi->op_status = OPERATING;

  return 0;
}

/* TODO fix this hazardous piece of code */
void scsi_free() {
  if (!scsi)
    kfree(scsi);

  scsi = NULL;
}

int scsi_up() {
  if (scsi == NULL)
    return 0;

  if (scsi->op_status == OPERATING)
    return 1;

  return 0;
}

/* 
 * Read driver parameters 
 */
struct capacity_data {
  uint32_t total_block_count;
  uint32_t block_size;
} __attribute__((packed));

static int scsi_read_capacity() {
  struct command_descriptor_block10 cdb10;
  struct capacity_data cap_data;
  int cap_data_size = sizeof(struct capacity_data);
  int rc;

  bzero((char *)&cdb10, cap_data_size);
  cdb10.op_code = CDB_READ_CAPACITY10;

  spinlock_acquire(&scsi->lock);
  rc = scsi->read(scsi->driver, 10, (char *)&cdb10, 
                                cap_data_size, (char *)&cap_data);
  spinlock_release(&scsi->lock);

  if (rc < 0)
    return rc;

  scsi->total_block_count = ntohl(cap_data.total_block_count);
  scsi->block_size = ntohl(cap_data.block_size);

  return 0;
}

/*
 * Read a number of blocks from the drive
 */
static int scsi_read_write(int dir, int block_start, 
                           int block_count, char *data) {
  int transfer_len;
  int rc;

  /* Command to SCSI server on the USB mass storage device */
  struct command_descriptor_block6 cdb6 = {
    .op_code = (dir == SCSI_READ) ? CDB_READ6: CDB_WRITE6,
    .length = block_count,  /* Unit of sectors */
    .control = 0
  };
  /*
   * Copy address omitting the first byte 
   * (SCSI addresses are 19bits long)
   */
  cdb6.block_address[0] = (block_start >> 16) & 0x1f;
  cdb6.block_address[1] = (block_start >> 8) & 0xff;
  cdb6.block_address[2] = block_start & 0xff;

  transfer_len = block_count * scsi->block_size;

  spinlock_acquire(&scsi->lock);
  if (dir == SCSI_READ)
    rc = scsi->read(scsi->driver, 6, (char *)&cdb6, 
                                  transfer_len, data);
  else
    rc = scsi->write(scsi->driver, 6, (char *)&cdb6, 
                                   transfer_len, data);
  spinlock_release(&scsi->lock);

  return rc;
}

/*
 * SCSI interface functions 
 */
int scsi_read(int block_start, int block_count, char *data) {
  int rc;

  if (scsi == NULL)
    return -1;

  rc = scsi_read_write(SCSI_READ, block_start, block_count, data);

  return rc;
}

int scsi_write(int block_start, int block_count, char *data) {
  int rc;

  if (scsi == NULL)
    return -1;

  rc = scsi_read_write(SCSI_WRITE, block_start, block_count, data);

  return rc;
}

