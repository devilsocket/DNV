from django.db import models

# Create your models here.
class DnvSession(models.Model):
	mobile = models.CharField(max_length=100, blank=True, null=True)
	group = models.CharField(max_length=100, blank=True, null=True)
	uploader = models.CharField(max_length=100, blank=True, null=True)
	src_ip = models.CharField(max_length=25)
	dst_ip = models.CharField(max_length=25)
	src_port = models.IntegerField(blank=True, null=True)
	dst_port = models.IntegerField(blank=True, null=True)
	start_time = models.DateTimeField(blank=True, null=True)
	end_time = models.DateTimeField(blank=True, null=True)
	pkts_num = models.IntegerField(blank=True, null=True)
	pkts_size = models.IntegerField(blank=True, null=True)
	session = models.BooleanField(default=1)
	hash = models.CharField(unique=True, max_length=100, blank=True, null=True)
	cat_one = models.TextField(blank=True)
	app_one = models.TextField(blank=True)
	subnet_one = models.TextField(blank=True)
	activity_one = models.TextField(blank=True)
	cat_two = models.TextField(blank=True)
	app_two = models.TextField(blank=True)
	domain_two = models.TextField(blank=True)
	activity_two = models.TextField(blank=True)
	pcap_file_path = models.TextField(blank=True)
	upload_id = models.CharField(max_length=100, blank=True, null=True)
	
	class Meta:
		managed = True
		db_table = 'DnvSession'

class DnvDns(models.Model):
	domain = models.TextField(blank=True)
	src_port = models.IntegerField(blank=True, null=True)
	dst_port = models.IntegerField(blank=True, null=True)
	src_ip = models.CharField(max_length=25)
	dst_ip = models.CharField(max_length=25)
	dns_time = models.DateTimeField(blank=True, null=True)
	type = models.CharField(max_length=25)
	hash = models.CharField(unique=True, max_length=100, blank=True, null=True)
	session = models.CharField(max_length=100, blank=True, null=True)
	upload_id = models.CharField(max_length=100, blank=True, null=True)

	class Meta:
		managed = True
		db_table = 'DnvDns'


class DnvUploadHistory(models.Model):
	file_name = models.CharField(max_length=100)
	upload_date = models.DateTimeField(blank=True, null=True)
	uploader = models.CharField(max_length=100)
	file_size = models.BigIntegerField(default=0)
	mobile = models.BigIntegerField(default=0)
	group = models.CharField(max_length=100)
	operation = models.CharField(max_length=10)
	upload_id = models.CharField(unique=True, max_length=100, blank=True, null=True)

	class Meta:
		managed = True
		db_table = 'DnvUploadHistory'



class DnvScanHistory(models.Model):
	scan_duration = models.BigIntegerField(default=0)
	scan_start_time = models.DateTimeField(blank=True, null=True)
	scan_end_time = models.DateTimeField(blank=True, null=True)
	mobile = models.BigIntegerField(default=0)
	group = models.CharField(max_length=100)
	uploader = models.CharField(max_length=100)
	session_count = models.BigIntegerField(default=0)
	upload_id = models.CharField(unique=True, max_length=100, blank=True, null=True)

	class Meta:
		managed = True
		db_table = 'DnvScanHistory'