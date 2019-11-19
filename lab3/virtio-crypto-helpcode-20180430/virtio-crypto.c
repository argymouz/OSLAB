/*
 * Virtio Crypto Device
 *
 * Implementation of virtio-crypto qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr> 
 *
 */

#include <qemu/iov.h>
#include "hw/virtio/virtio-serial.h"
#include "hw/virtio/virtio-crypto.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint32_t get_features(VirtIODevice *vdev, uint32_t features)
{
	DEBUG_IN();
	return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
	DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
	DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
	VirtQueueElement elem;
	unsigned int *syscall_type;
	int *host_fd;
	int* ret;
	unsigned int* ioctl_cmd;
	DEBUG_IN();

	char output_str[100];
	if (!virtqueue_pop(vq, &elem)) {
		DEBUG("No item to pop from VQ :(");
		return;
	} 

	DEBUG("I have got an item from VQ :)");

	if ((host_fd = (int *) malloc(sizeof(int))) == NULL) {
		perror("out of mem");
		exit(1);
	}
	syscall_type = elem.out_sg[0].iov_base;
	switch (*syscall_type) {
		case VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN:
			DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN");
			host_fd = elem.in_sg[0].iov_base;
			*host_fd = open("/dev/crypto", O_RDWR);
			if (*host_fd < 0){
				DEBUG("I WAS UNABLE TO OPEN /dev/crypto");	
				perror("open");
				return;
			}
			sprintf(output_str,"I WAS ABLE TO OPEN /dev/crypto returning %d",*host_fd);
			DEBUG(output_str);
			break;
	
		case VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE:
			DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE");
			host_fd = elem.out_sg[1].iov_base;
			if (close(*host_fd) < 0){
				perror("close");
				return;
			}
			break;
	
		case VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL:
			DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL");
			host_fd = elem.out_sg[1].iov_base;
			ioctl_cmd = elem.out_sg[2].iov_base;
			sprintf(output_str,"I GOT IOCTL = %u", *ioctl_cmd);		
			DEBUG(output_str);
			switch(*ioctl_cmd) {
				case CIOCGSESSION:
					DEBUG("CIOCGSESSION");	
					struct session_op *session_op = elem.in_sg[0].iov_base;				
					unsigned char *session_key = elem.out_sg[3].iov_base;
					ret=elem.in_sg[1].iov_base;
					session_op->key = session_key;
					if(ioctl(*host_fd,CIOCGSESSION,session_op)){
						*ret = -1;
						perror("ioctl");
					} 
					else *ret = 0;
					break;
			
				case CIOCFSESSION:
					DEBUG("CIOCFSESSION");
					int* ses_id = elem.out_sg[3].iov_base;
					ret=elem.in_sg[0].iov_base;
					if(ioctl(*host_fd,CIOCFSESSION,ses_id)) {
						perror("ioctl");
						*ret=-1;
					}
					else *ret=0;
					break;
				
				case CIOCCRYPT:
					DEBUG("CIOCRYPT");
					struct crypt_op* crypt_op = elem.out_sg[3].iov_base;
					unsigned char *src = elem.out_sg[4].iov_base;
					unsigned char *iv = elem.out_sg[5].iov_base;
					unsigned char *dst = elem.in_sg[0].iov_base;
					ret = elem.in_sg[1].iov_base;
					crypt_op->src=src;
					crypt_op->iv=iv;
					crypt_op->dst=dst;
					
					if(ioctl(*host_fd,CIOCCRYPT,crypt_op)) {
						perror("ioctl");
						*ret= -1;
					}
					else *ret=0;
					break;
				default:
					DEBUG("Unrecognised ioctl");
					break;
			}
			break;
		default:
			DEBUG("Unknown syscall_type");
			break;
	}
	
	virtqueue_push(vq, &elem, 0);
}

static void virtio_crypto_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

	DEBUG_IN();

    virtio_init(vdev, "virtio-crypto", 13, 0);
	virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_crypto_unrealize(DeviceState *dev, Error **errp)
{
	DEBUG_IN();
}

static Property virtio_crypto_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_crypto_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

	DEBUG_IN();
    dc->props = virtio_crypto_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_crypto_realize;
    k->unrealize = virtio_crypto_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
};

static const TypeInfo virtio_crypto_info = {
    .name          = TYPE_VIRTIO_CRYPTO,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCrypto),
    .class_init    = virtio_crypto_class_init,
};

static void virtio_crypto_register_types(void)
{
    type_register_static(&virtio_crypto_info);
}

type_init(virtio_crypto_register_types)
