static ssize_t write(struct file *filp, const char __user *buf, ssize_t len, loff_t *pos)
{
	int i;
	ssize_t ret;
	unsigned long flags;
#define TMP_SIZE 1024
	char tmp_buf[TMP_SIZE];

	struct cache_device *cache;

	cache = filp->private_data;
	WARN_ON(!cache);

	if (len > TMP_SIZE) {
		len = TMP_SIZE;
	}

	spin_lock_irqsave(&cache->lock, flags);
	while (cache->cnt == BUF_SIZE) {
		if (!cache->flush_in_progress) {
			cache->flush_in_progress = 1;
			initiate_flush(cache);
		}
		while (cache->flush_in_progress) {
			spin_unlock_irqrestore(&cache->lock, flags);
			if (wait_event_interruptible(cache->wq, (cache->cnt != BUF_SIZE) && (!cache->flush_in_progress))) {
				return -ERESTARTSYS;
			}
			spin_lock_irqsave(&cache->lock, flags);
		}
	}
	if (len > BUF_SIZE - cache->cnt) {
		len = BUF_SIZE - cache->cnt;
	}
	spin_unlock_irqrestore(&cache->lock, flags);

	if (copy_from_user(tmp, buf, len)) {
		return -EFAULT;
	}

	spin_lock_irqsave(&cache->lock, flags);
	for (i = 0; i < len; i++) {
		cache->buf[i + cache->cnt] = tmp_buf[i];
	}
	cache->cnt += len;
	spin_unlock_irqrestore(&cache->lock, flags);

	ret = len;
	return ret;
}

void flush_completed(unsigned int intr_mask)
{
	unsigned long flags;

	if (!intr_mask) spin_lock(&cache->lock);
	else spin_lock_irqsave(&cache->lock, flags);
	cache->cnt = 0;
	cache->flush_in_progress = 0;
	wake_up_interruptible(&cache->wq);
	if (!intr_mask) spin_unlock(&cache->lock);
	else spin_unlock_irqrestore(&cache->lock, flags);
}
