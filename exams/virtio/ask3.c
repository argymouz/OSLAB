/* The struct that is being exchanged via the virtqueue. */
struct crypto_buffer {
	char *input; /* The input string. */
	char *output; /* The output string. */
	unsigned int len; /* The length of the input. */
	char *key; /* The key used for encryption/decryption. */
	unsigned int key_len;  /* The length of the key. */
};

struct crypto_device {
	struct virtqueue *vq;
	struct semaphore vq_lock;
} crypto_dev;

static long virtio_crypto_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct statterlist cmd_sg, cbuf_sg, cbuf_input_sg, cbuf_output_sg, cbuf_key_sg, *sgs[5];
	struct crypto_device *cdev = &crypto_dev;
	struct crypto_buffer *cbuf;
	char *input_ptr, *output_ptr, *key_ptr;
	unsigned int len;
	long ret = 0;

	/* Fetch all necessary data from userspace. */
	cbuf = kzalloc(sizeof(*cbuf), GFP_KERNEL);
	if (!cbuf) return -ENOMEM;
	if (copy_from_user(cbuf, (struct crypto_buffer *) arg, sizeof(*cbuf))) {
		ret = -EFAULT;
		goto out;
	}

	len = cbuf->len;
	input_ptr = kzalloc(len*sizeof(char), GFP_KERNEL);
	if (!input_ptr) {
		ret = -ENOMEM;
		goto out;
	}
	if (copy_from_user(input_ptr, cbuf->input, len)) {
		ret = -EFAULT;
		goto free_input_ptr;
	}

	key_ptr = kzalloc(cbuf->key_len*sizeof(char), GFP_KERNEL);
	if (!key_ptr) {
		ret = -ENOMEM;
		goto free_output_ptr;
	}
        if (copy_from_user(key_ptr, cbuf->key, key_len)) {
                ret = -EFAULT;
                goto free_key_ptr;
        }

        output_ptr = kzalloc(len*sizeof(char), GFP_KERNEL);
	if (!output_ptr) {
		ret = -ENOMEM;
		goto free_input_ptr;
	}

	switch (cmd) {
		case ENCRYPT:
		case DECRYPT:
			sg_init_one(&cmd_sg, &cmd, sizeof(cmd));	
			sg[0] = &cmd_sg;

			sg_init_one(&cbuf_sg, cbuf, sizeof(*cbuf));
			sg[1] = &cbuf_sg;

			sg_init_one(&cbuf_input_sg, input_ptr, len);	
			sg[2] = &cbuf_input_sg;

			sg_init_one(&cbuf_key_sg, key_prt, key_len);	
			sg[3] = &cbuf_key_sg;

			sg_init_one(&cbuf_output_sg, output_ptr, len);	
			sg[4] = &cbuf_output_sg;

			/* Send sgs and notify the host. */
			down_interruptible(&c_dev->vq_lock);
			if (virtqueue_add_sgs(c_dev->vq, sgs, 4, 1, cbuf, GFP_ATOMIC)) {
				up(&c_dev->vq_lock);
				ret = -EINVAL;
				goto free_key_ptr;
			}
			virtqueue_kick(vq);

			/* Spin on the virtqueue until the buffer is back. */
			while (virtqueue_get_buf(c_dev->vq, &len) == NULL)
				/* do nothing */;
			up(&c_dev->vq_lock);

		break;

		default:
			ret = -EINVAL;
			goto free_output_ptr;
	}

	/* Copy all necessary data back to userspace. */
	if (copy_to_user((struct crypto_buffer *) arg, cbuf, sizeof(*cbuf))) ret = -EINVAL;

out:
	kfree(key_ptr);
	kfree(output_ptr);
	kfree(input_ptr);
	kfree(cbuf);
	return ret;
}

void vq_crypto_callback(VirtIODevice *vdev, VirtQueue *vq)
{
	VirtQueueElement elem;
	struct crypto_buffer *cbuf;
	char *input, *output, *key;
	int ret;
	int fd; /* This is an open instance of /dev/crypto on the host. */
	char *input_saved, *output_saved, *key_saved;
	unsigned int cmd;

	if (!virtqueue_pop(vq, &elem))
		return;

	cmd = *elem.out_sg[0].iov_base;
	cbuf = *elem.out_sg[1].iov_base;
	input = *elem.out_sg[2].iov_base;
	key = *elem.out_sg[3].iov_base;
	output = *elem.in_sg[0].iov_base;
	cbuf->input = input;
	cbuf->key = key;
	cbuf->output = output;

	/* ioctl() to the host device driver, it is always successful. */
	ret = ioctl(fd, cmd, cbuf);
	if (ret < 0) perror("ioctl");

	virtqueue_push(vq, &elem, 0);
	virtio_notify(vdev, vq);
}
