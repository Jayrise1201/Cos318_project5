#include "../util.h" 
#include "error.h"
#include "pci.h"
#include "debug.h"
#include "allocator.h"
#include "uhci_pci.h"
#include "ehci_pci.h"

DEBUG_NAME("PCI");

static struct list pci_drv_list_head;
static struct list pci_dev_list_head;

/* function prototypes */
static void pci_scan_slots();

static int pci_dev_exists(uint32_t bus, uint32_t slot, uint32_t func);
static uint32_t pci_read_reg32(uint32_t bus, uint32_t slot, 
                               uint32_t func, uint32_t offset);

/* 
 * PCI initialisation function 
 *
 * It just clears the statically allocated memory area for PCI devices
 * and scans PCI slots querring the attached cards. 
 */
void pci_static_init() {
  DEBUG("Initialising PCI subsystem...");

  LIST_INIT(&pci_drv_list_head);
  LIST_INIT(&pci_dev_list_head);

  /* Register UHCI and EHCI device drivres */
  uhci_pci_dev_driver_register();
  ehci_pci_dev_driver_register();

  /* Scan PCI slots */
  pci_scan_slots();
}

static void pci_print_device_info(struct pci_dev *dev) {

  if (dev == NULL)
    return;

  DEBUG("Found PCI device:");
  DEBUG("  Vendor: 0x%04x, Device: 0x%04x",dev->vendor, dev->device);
  DEBUG("  Class: 0x%02x, Subclass: 0x%02x, ProgIF: 0x%02x", 
      dev->class_code, dev->subclass_code, dev->prog_ifc);
  DEBUG("  Location:  Bus: %d, Slot: %d", 
      dev->bus, dev->slot);
  DEBUG("  Interrupt line: %d", dev->interrupt_line);

  return;
}

static int pci_lookup_driver(struct pci_dev *dev) {
  struct pci_dev_driver *pdd;
  struct pci_driver_list *pdl;

  LIST_FOR_EACH(&pci_drv_list_head, pdl) { 
    pdd = pdl->drv;
    if ((dev->class_code == pdd->class_code) &&
        (dev->subclass_code == pdd->subclass_code) &&
        (dev->prog_ifc == pdd->prog_ifc)) {
      /* Bind the interrupt rutine */
      dev->interrupt = pdd->interrupt;
      /* Initialise the device driver and return */
      return pdd->init(dev);
    }
  }

  return ERR_NO_DRIVER; 
}

static int pci_init_device(unsigned int bus, unsigned int slot,
                     unsigned int func) {
  struct pci_dev *dev;
  int cfunc;
  int err;

  dev = kzalloc(sizeof(struct pci_dev));
  if (dev == NULL)
    return ERR_NO_MEM;

  /* Fill in basic information about this PCI device */
  dev->bus = bus;
  dev->slot = slot;
  dev->func = func;
  dev->vendor = pci_read_dev_reg16(dev, PCI_DEV_VENDOR);
  dev->device = pci_read_dev_reg16(dev, PCI_DEV_DEVICE);
  dev->class_code = pci_read_dev_reg8(dev, PCI_DEV_CLASS);
  dev->subclass_code = pci_read_dev_reg8(dev, PCI_DEV_SUBCLASS);
  dev->prog_ifc = pci_read_dev_reg8(dev, PCI_DEV_PROG_IF);
  dev->header = pci_read_dev_reg8(dev, PCI_DEV_HEADER);
  dev->interrupt_line = pci_read_dev_reg8(dev, PCI_DEV_INT_LINE);
  
  /*
   * Linking procedure cannot be interrupted by PCI interrupt 
   * that traverses the list 
   */
  enter_critical();
  LIST_LINK(&pci_dev_list_head, dev);
  leave_critical();

  pci_print_device_info(dev);

  err = pci_lookup_driver(dev);
  if (err == 0)
    dev->op_state = DEV_STATUS_OPERATING;
  else if (err == ERR_NO_DRIVER)
    dev->op_state = DEV_STATUS_NO_DRIVER;
  else if (err == ERR_NO_MEM) 
    dev->op_state = DEV_STATUS_NO_DRIVER;
  else 
    dev->op_state = DEV_STATUS_UNKNOWN;

  /*
   * Check whether this is a PCI device with multiple functions
   * If a PCI device has multiple functions, it is indicated in 
   * the header field with MF bit.We register different functions of
   * a PCI device as new devices 
   */
  if (((dev->header & PCI_DEV_HEADER_MF_BIT) != 0) && (func == 0))
    for (cfunc = 1; cfunc < 8; cfunc++)
      if (pci_dev_exists(dev->bus, dev->slot, cfunc))
          pci_init_device(dev->bus, dev->slot, cfunc);

  return 0;  
}

/*
 * A device driver calls this function to register on
 * the PCI device drivers list. Later, the registered device
 * drivers are matched against devices found on the PCI bus.
 */
int pci_dev_driver_register(struct pci_dev_driver *pdd) {
  struct pci_driver_list *pdl;

  pdl = kzalloc(sizeof(struct pci_driver_list));
  if(pdl == NULL)
    return ERR_NO_MEM;

  DEBUG("Registering a driver for the device of class %02x, subclass %02x, interface %02x",
      pdd->class_code, pdd->subclass_code, pdd->prog_ifc);
  pdl->drv = pdd;
  LIST_LINK(&pci_drv_list_head, pdl);

  return 0;
}

static void pci_scan_slots() {
  int bus;
  int slot;
  const int func = 0;

  /*
   * Each PCI bus can have up to 32 slots and each PCI device
   * can have up to 8 functions. Devices with multiple functions
   * are scanned during the device initialisation phase
   */
  for (bus = 0; bus < 1; bus++)
    for (slot = 0; slot < 32; slot++)
        if(pci_dev_exists(bus, slot, func)) 
          pci_init_device(bus, slot, func);

  return;
}

/* 
 * PCI interrupt handler
 *
 * A PCI device interrupt pin is connected to one of four PCI interrupt
 * lines: PIRQA, PIRQB, PIRQC, or PIRQD. These PCI interrupt lines are 
 * routed via PIR to the 5th line of the master PIC and the 9th, 10th, 
 * or 11th line of the slave PIC.  When the PCI interrupt fires, 
 * this function is called with an argument containing the PIC line number
 * that caused this interrupt call. 
 * 
 * The PIC line the PCI device is connected to is stored in the PCI device
 * header. This mapping is done by BIOS during initialisation process. 
 * Many PCI devices can use the same interrupt line. However, we leave verification 
 * of the interrupt event for the device driver.
 */
void pci_interrupt(int int_line) {
  struct pci_dev *dev;

  /* Find PCI devices that could trigger this interrupt */
  LIST_FOR_EACH(&pci_dev_list_head, dev)
    if ((dev->op_state == DEV_STATUS_OPERATING) &&
        (dev->interrupt_line == int_line)) 
        dev->interrupt(dev->driver);

  return;
}

static int pci_dev_exists(unsigned int bus, unsigned int slot,
                   unsigned int func) {
  uint16_t vendor_id;

  vendor_id = (uint16_t)(pci_read_reg32(bus, slot, func, 0) & 0xffff);
  /* Vendor ID value of 0xffff indicates empty slot */
  if (vendor_id == 0xffff) 
    return 0;
  else
    return 1;
}

/* Reads a PCI register value */ 
static uint32_t pci_read_reg32(uint32_t bus, uint32_t slot,
                      uint32_t func, uint32_t offset) {
  uint32_t command;

  /* Assemble command 
   * 31     30-24    23-16 15-11 10-8     7-0
   * Enable reserved bus   slot  function (offset & 0xfc)
   */
  command = (1 << 31) | (bus << 16) | (slot << 11) | (func << 8) | (offset & 0xfc);
  outl(PCI_HB_IO_CONFIG_ADDRESS, command);
  return inl(PCI_HB_IO_CONFIG_DATA);
}

uint32_t pci_read_dev_reg32(struct pci_dev *dev, uint32_t offset) {
  if (dev == NULL) 
    return 0;

  return pci_read_reg32(dev->bus, dev->slot, dev->func, offset);
}

uint16_t pci_read_dev_reg16(struct pci_dev *dev, uint32_t offset) {
  uint32_t reg32;

  if (dev == NULL)
    return 0;

  reg32 = pci_read_dev_reg32(dev, offset);

  if ((offset & 2) == 0)
    return (uint16_t)(reg32 & 0xffff);
  else
    return (uint16_t)((reg32 & 0xffff0000) >> 16);
}

uint8_t pci_read_dev_reg8(struct pci_dev *dev, uint32_t offset) {
  uint16_t reg16;

  if (dev == NULL)
    return 0;

  reg16 = pci_read_dev_reg16(dev, offset);
  
  if ((offset & 1) == 0)
    return (uint8_t)(reg16 & 0xff);
  else
    return (uint8_t)((reg16 & 0xff00) >> 8);
}


/* Writes a PCI register value */
static void pci_write_reg32(uint32_t bus, uint32_t slot,
                       uint32_t func, uint32_t offset, uint32_t data) {
  unsigned int command;

  /* Assemble command according to the pattern 
   * 31     30-24    23-16 15-11 10-8     7-0
   * Enable reserved bus   slot  function (offset & 0xfc)
   */
  command = (1 << 31) | (bus << 16) | (slot << 11) | (func << 8) | (offset & 0xfc);
  outl(PCI_HB_IO_CONFIG_ADDRESS, command);
  outl(PCI_HB_IO_CONFIG_DATA, data);
}

void pci_write_dev_reg32(struct pci_dev *dev, uint32_t offset, uint32_t data) {
  if (dev == NULL) 
    return;

  pci_write_reg32(dev->bus, dev->slot, dev->func, offset, data);

  return;
}

void pci_write_dev_reg16(struct pci_dev *dev, uint32_t offset, uint16_t data) {
  uint32_t reg32;
  if (dev == NULL)
    return;
  
  reg32 = pci_read_dev_reg32(dev, offset);

  if((offset & 2) == 0)
    reg32 = (reg32 & 0xffff0000) | data;
  else
    reg32 = (reg32 & 0xffff) | (((uint32_t)data) << 16);

  pci_write_dev_reg32(dev, offset & 0xfc, reg32);

  return;
}

void pci_write_dev_reg8(struct pci_dev *dev, uint32_t offset, uint8_t data) {
  uint32_t reg32;
  if (dev == NULL)
    return;
  
  reg32 = pci_read_dev_reg32(dev, offset);

  switch (offset & 3) {
    case 0: reg32 = (reg32 & 0xffffff00) | data; break;
    case 1: reg32 = (reg32 & 0xffff00ff) | (((uint32_t)data) << 8); break;
    case 2: reg32 = (reg32 & 0xff00ffff) | (((uint32_t)data) << 16); break;
    case 3: reg32 = (reg32 & 0x00ffffff) | (((uint32_t)data) << 24); break;
    default:;
  }

  pci_write_dev_reg32(dev, offset & 0xfc, reg32);

  return;
}

