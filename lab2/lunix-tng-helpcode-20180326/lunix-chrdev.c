/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * Argyris Mouzakis, Nikos Mouzakis
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	
	WARN_ON ( !(sensor = state->sensor));
	if (state->buf_timestamp != sensor->msr_data[state->type]->last_update) { // if the timestaps are different, refreshing is necessary
		return 1;
	}
	return 0;
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	uint32_t value, timestamp;
	int i;
	long lookup_table_value, integer_part, decimal_part;
	unsigned long flags;
	
	debug("start of update function\n");

	if (!lunix_chrdev_state_needs_refresh(state)) { // if there aren't any new values
		debug("leaving update function, no new data\n");
		return -EAGAIN; // return with the value expected by read
	}

	debug("we start copying the new data from the sensor buffers\n");

	sensor = state->sensor;
	WARN_ON(!sensor);
	
	// since we are interacting with the sensor, use spinlocks instead of semaphores
	// that is because the sensors interact with the discipline as well
	// whose function is based on hardware interrupts
	// and hardware interrupts are dealt with spinlocks
	// since semaphores are mainly for processes
	// we use the versions of the spinlock functions that disable interrupts temporarily
	spin_lock_irqsave(&sensor->lock, flags);
	value = sensor->msr_data[state->type]->values[0];
	timestamp = sensor->msr_data[state->type]->last_update;
	spin_unlock_irqrestore(&sensor->lock, flags);

	// convert using the lookup tables
	if (state->type == 0) lookup_table_value = lookup_voltage[value];
	else if (state->type == 1) lookup_table_value = lookup_temperature[value];
	else lookup_table_value = lookup_light[value];
	debug("the value we got from the lookup tables is %ld\n", lookup_table_value);

	// start converting to user space form

	state->buf_lim = 0;

	// first, let's get the sign right

	if (lookup_table_value < 0) {
		state->buf_data[state->buf_lim++] = '-';
		lookup_table_value = -lookup_table_value;
	}

	// all values are meant to have 3 decimal digits
	// in the lookup_tables, all values where multiplied by 1000 and then converted from double to long, so as to avoid dealing with real numbers
	// now, to get the integer part, we have to divide by 1000
	// and the decimal part is mod 1000

	integer_part = lookup_table_value/1000;
	decimal_part = lookup_table_value%1000;

	if (integer_part == 0) {
		state->buf_data[state->buf_lim++] = '0';
		i = 0;
	}
	else {
		i = 1;
		while (integer_part >= i) i *= 10;
		i /= 10;
	}
	while (i != 0) {
		state->buf_data[state->buf_lim++] = (unsigned char) (integer_part/i + 48);
		integer_part %= i;
		i /= 10;
	}

	state->buf_data[state->buf_lim++] = '.'; // the decimal point

	i = 1;
	state->buf_lim += 3; // we have three positions for decimals
	while (i <= 3) {
		state->buf_data[state->buf_lim - i] = (unsigned char) (decimal_part%10 + 48);
		decimal_part /= 10;
		i++;
	}

	state->buf_data[state->buf_lim++] = '\n';
	state->buf_data[state->buf_lim] = '\0';
	state->buf_timestamp = timestamp; // since the procedure has finished, renew the timestamp
	
	debug("leaving update with msr %s, %d\n", state->buf_data, state->buf_lim);
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	int ret;
	unsigned int dev_minor_num, type;
	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	debug("entering open phase\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */
	dev_minor_num = iminor(inode); // get the device's minor number
	debug("the device has minor number %d, the corresponding sensor is %d\n", dev_minor_num, dev_minor_num/8);
	sensor = &lunix_sensors[dev_minor_num/8]; // find the corresponding sensor structure (for lunix_sensors, see lunix-module.c)
	type = dev_minor_num%8; // find the num corresponding to the msr type
	
	/* Allocate a new Lunix character device private state structure */
	state = (struct lunix_chrdev_state_struct*) vmalloc(sizeof(struct lunix_chrdev_state_struct)); // allocate memory for a private state structure
	if (!state) { // check if vmalloc failed (highly unlikely, the kernel has unlimited access to memory)
		printk(KERN_ERR "Failed to allocate memory for Lunix character device state structure\n");
		ret = -ENOMEM;
		goto out;
	}
	state->sensor = sensor; // associate the private state structure with the corresponding sensor 
	state->type = type; // save the number corresponding to the type of msr
	state->buf_lim = 0; // buf_lim is initially 0
	sema_init(&state->lock, 1); // initialize the structure's semaphore
	filp->private_data = state; // the state structure's adress should be saved in filp->private_data

out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	vfree(filp->private_data); // since vmalloc was used, we have to use vfree
	debug("closing down (release)\n");
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	debug("ioctl was not implemented, the program shouldn't be here\n");
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	debug("about to read from sensor\n");
	if (down_interruptible(&state->lock)){
		return -ERESTARTSYS;
	} 

	// the program enters the body of the following if stmt when we are at the start of a new msr (that's when *f_pos == 0)

	if (*f_pos == 0) { // update the state structure with the new msr
		while (lunix_chrdev_state_update(state) == -EAGAIN) { // if the update fails, get in the body of the loop
			up(&state->lock); // we don't need the semaphore at this point, since we are not reading from the sensor
			if (filp->f_flags & O_NONBLOCK) // if the user has asked non-blocking I/O, return
				return -EAGAIN;
			debug("\"%s\" reading: going to sleep\n", current->comm); // https://stackoverflow.com/questions/22346545/current-in-linux-kernel-code
			if (wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state))) { // implements blocking I/O
				debug("restart read by ctrl+c");
				return -ERESTARTSYS; // https://www.linuxtv.org/downloads/v4l-dvb-internals/device-drivers/API-wait-event-interruptible.html
			}
			debug("\"%s\" has woken up and reached this point of execution, new data must be available!\n", current->comm);
			if (down_interruptible(&state->lock)) { // when restarting, re-acquire the semaphore
				return -ERESTARTSYS;
			}
		}
	}

	if (*f_pos >= state->buf_lim*sizeof(unsigned char)) { // under normal circumstances, this is unreachable
		debug("reached eof, nothing to copy");
		*f_pos = 0;
		ret = 0;
		goto out;
	}

	if (*f_pos + cnt > state->buf_lim*sizeof(unsigned char)) {
		cnt = state->buf_lim*sizeof(unsigned char) - *f_pos;
		debug("more bytes requested than existing, new cnt is %d", (int) cnt);
	}

	debug("about to copy %d bytes", (int) cnt);
	if (copy_to_user(usrbuf, state->buf_data + *f_pos, cnt)) {
		debug("user gave invalid adress");
		ret = -EFAULT;
		goto out;
	}

	*f_pos += cnt;
	ret = cnt;
	if (*f_pos == state->buf_lim*sizeof(unsigned char)) {
		debug("reached eof, rewinding");
		*f_pos = 0;
	}

out:
	up(&state->lock);
	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	debug("mmap was not implemented, the program shouldn't be here\n");
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
        .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	
	debug("initializing character device\n");
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, lunix_minor_cnt, "Lunix:TNG");
	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}
	debug("device registered successfully with dev_no %d and range %d\n", (int) dev_no, (int) lunix_minor_cnt);
	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
		
	debug("entering destruction phase\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving destruction phase\n");
}
