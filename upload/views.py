from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.core.files.storage import FileSystemStorage
import zipfile, os, datetime, hashlib, zipfile
import os.path, hashlib
from django.shortcuts import redirect
from pprint import pprint

# some constants
SITE_ROOT = os.path.dirname(os.path.realpath(__file__))
ZIP_DIR_NAME = "DNV_ZIP_UPLOADS"
# models starts here
from dashboard.models import DnvUploadHistory, DnvSession, DnvDns, DnvScanHistory
# load dnv modules
from .DnvEngine.pkt import PacketDiessector


# some custom functions
def dnv_unzipper(zip_file_path, file_name):
	file_name = file_name.split('.')[0]
	unzip_dir = os.path.join(settings.MEDIA_ROOT, 'DNV_UNZIP', file_name)
	if not os.path.exists(unzip_dir):os.makedirs(unzip_dir)
	zip_ref = zipfile.ZipFile(zip_file_path, 'r')
	zip_ref.extractall(unzip_dir)
	zip_ref.close()
	return unzip_dir

def dnv_dir_walk(main_dir,mobile,group,uploader,upload_id):
	res = {}
	start = datetime.datetime.now()
	session_count = 0
	dns_count = 0
	for root,dirs,files in os.walk(main_dir):
		if files:
			for file in files:
				fpath = os.path.join(root,file)
				if os.path.exists(fpath):
					if fpath.endswith('.pcap'):
						dnv_sessions = PacketDiessector(fpath,upload_id)
						if dnv_sessions:
							bulk_list = []
							dns_list = []
							for dnv_session in dnv_sessions:
								session_count+=1
								ds = DnvSession()
								ds.mobile = mobile
								ds.group = group
								ds.uploader = uploader
								ds.src_ip = dnv_session['src_ip']
								ds.dst_ip = dnv_session['dst_ip']
								ds.src_port = dnv_session['src_port']
								ds.dst_port = dnv_session['dst_port']
								ds.start_time = dnv_session['start_time']
								ds.end_time = dnv_session['end_time']
								ds.pkts_num = dnv_session['pkts_num']
								ds.pkts_size = dnv_session['pkts_size']
								ds.session = dnv_session['session']
								ds.hash = dnv_session['hash']
								ds.pcap_file_path = dnv_session['pcap_file_path']
								ds.upload_id = dnv_session['upload_id']
								if dnv_session['phase_one_scan']:
									ds.cat_one = dnv_session['phase_one_scan']['category']
									ds.app_one = dnv_session['phase_one_scan']['application']
									ds.subnet_one = dnv_session['phase_one_scan']['subnet']
									activity_one = dnv_session['phase_one_scan']['activity']
								if dnv_session['phase_two_scan']:
									ds.cat_one = dnv_session['phase_two_scan']['category']
									ds.app_one = dnv_session['phase_two_scan']['application']
									ds.domain_one = dnv_session['phase_two_scan']['domain']
									ds.activity_one = dnv_session['phase_two_scan']['activity']
								bulk_list.append(ds)
								if dnv_session['dns_data']:
									dns_count+=1
									dns_d = dnv_session['dns_data']
									dns_d['session'] = dnv_session['hash']
									dns_d['hash'] = hashlib.md5(str(dnv_session.values()).encode('utf-8')).hexdigest()
									ddn = DnvDns()
									ddn.domain = dns_d['domain']
									ddn.src_port = dns_d['src_port']
									ddn.dst_port = dns_d['dst_port']
									ddn.src_ip = dns_d['src_ip']
									ddn.dst_ip = dns_d['dst_ip']
									ddn.dns_time = dns_d['dns_time']
									ddn.type = dns_d['type']
									ddn.hash = dns_d['hash']
									ddn.session = dns_d['session']
									ddn.upload_id = dns_d['upload_id']
									dns_list.append(ddn)
							DnvSession.objects.bulk_create(bulk_list)
							if dns_list:
								DnvDns.objects.bulk_create(dns_list)
	res['session_count'] = session_count
	res['dns_count'] = dns_count
	end = datetime.datetime.now()
	took = (end-start).seconds
	res['scan_start'] = start.strftime("%Y-%m-%d %H:%M:%S")
	res['scan_stop'] = end.strftime("%Y-%m-%d %H:%M:%S")
	res['scan_duration'] = took
	return res



@login_required
def upload_root(request):
	identity = "Upload"
	data = {
		'title' : identity,
		'page' : 'Upload zip containing pcap files',
		'path' : [identity],
	}
	data['upload_history'] = DnvUploadHistory.objects.filter(uploader=request.user).all().order_by('-upload_date')
	data['scan_history'] = DnvScanHistory.objects.filter(uploader=request.user).all().order_by('-scan_end_time')
	return render(request, 'upload/upload.html', data)


@login_required
def upload_pcap(request):
	identity = "Upload"
	data = {
		'title' : identity,
		'page' : 'Upload Complete',
		'path' : [identity],
	}
	if request.method == 'POST' and request.FILES['myfile']:
		myfile = request.FILES['myfile']
		fs = FileSystemStorage()
		filename = myfile.name
		filepath = fs.save(os.path.join(ZIP_DIR_NAME,myfile.name), myfile)
		data['path'].append(filename)
		uploaded_file_url = fs.url(filepath)
		abs_file_url = SITE_ROOT.replace('upload','')+uploaded_file_url
		file_stat = list(os.stat(abs_file_url))
		data['file_name'] = filename
		data['zip_path'] = abs_file_url
		data['size'] = os.path.getsize(abs_file_url)
		data['upload_date'] = str(datetime.datetime.fromtimestamp(file_stat[-1]).strftime('%Y-%m-%d %H:%M:%S'))
		data['mobile'] = request.POST.get('mobileNumber')
		data['group'] = request.POST.get('groupName')
		data['uploader'] = str(request.user)
		data['operation'] = 'Uploaded'
		upload_hash = "{}{}{}{}{}{}{}".format(data['file_name'],data['upload_date'],data['uploader'],data['size'],data['mobile'],data['group'],data['operation']).encode()
		data['upload_id'] = str(hashlib.md5(upload_hash).hexdigest())
		duh = DnvUploadHistory(file_name=data['file_name'],upload_date=data['upload_date'],mobile=data['mobile'],uploader=data['uploader'],file_size=data['size'],group=data['group'],operation=data['operation'],upload_id=data['upload_id'])
		duh.save()		
		return render(request, 'upload/upload_done.html', data)
	return render(request, 'upload/upload.html', data)

@login_required
def scan_pcap(request):
	identity = "Scan"
	data = {
		'title' : identity,
		'page' : 'Scanning Uploaded File',
		'path' : [identity],
	}
	if request.method == 'POST' and request.FILES['myfile']:
		myfile = request.FILES['myfile']
		fs = FileSystemStorage()
		filename = fs.save(myfile.name, myfile)
		data['path'].append(filename)
		uploaded_file_url = fs.url(filename)
		abs_file_url = SITE_ROOT.replace('upload','')+uploaded_file_url
		file_stat = list(os.stat(abs_file_url))
		data['file_name'] = filename
		data['zip_path'] = abs_file_url
		data['size'] = os.path.getsize(abs_file_url)
		data['upload_date'] = datetime.datetime.fromtimestamp(file_stat[-1]).strftime('%Y-%m-%d %H:%M:%S')
		data['mobile'] = request.POST.get('mobileNumber')
		data['group'] = request.POST.get('groupName')
		print(data)
		return render(request, 'upload/upload_done.html', data)
	return render(request, 'upload/upload.html', data)

@login_required
def remove_pcap(request):
	identity = "Remove"
	data = {
		'title' : identity,
		'page' : 'Removing Uploaded File',
		'path' : [identity],
	}
	if request.method == 'POST':
		if 'file_path' in request.POST and 'file_name' in request.POST:
			file_path = request.POST.get('file_path')
			file_name = request.POST.get('file_name')
			if os.path.exists(file_path):os.remove(file_path)
			data['del_file_name'] = file_name
			data['file_name'] = request.POST.get('file_name')
			data['upload_date'] = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
			data['uploader'] = request.POST.get('uploader')
			data['size'] = request.POST.get('size')
			data['mobile'] = request.POST.get('mobile')
			data['group'] = request.POST.get('group')
			data['operation'] = 'Deleted'
			upload_hash = "{}{}{}{}{}{}{}".format(data['file_name'],data['upload_date'],data['uploader'],data['size'],data['mobile'],data['group'],data['operation']).encode()
			duh = DnvUploadHistory(file_name=data['file_name'],upload_date=data['upload_date'],mobile=data['mobile'],uploader=data['uploader'],file_size=data['size'],group=data['group'],operation=data['operation'],upload_id=str(hashlib.md5(upload_hash).hexdigest()))
			print(duh)
			duh.save()
			return render(request, 'upload/upload_remove.html', data)
	return render(request, 'upload/upload.html', data)


@login_required
def remove_pcap_entry(request, u_id):
	identity = "Upload"
	data = {
		'title' : identity,
		'page' : 'Upload zip containing pcap files',
		'path' : [identity],
	}
	instance = DnvUploadHistory.objects.get(upload_id=u_id)
	instance.delete()
	response = redirect('/upload/')
	return response

@login_required
def passive_execute(request):
	identity = "Passive Scanner"
	data = {
		'title' : identity,
		'page' : 'Passive/Offline Packet Scanner',
		'path' : [identity],
	}
	if request.method == 'POST':
		file_path = request.POST.get('file_path')
		file_name = request.POST.get('file_name')
		mobile = request.POST.get('mobile')
		group = request.POST.get('group')
		uploader = request.POST.get('uploader')
		upload_id = request.POST.get('upload_id')
		unzip_dir = dnv_unzipper(file_path, file_name)
		#p = Process(target=dnv_dir_walk, args=(unzip_dir,mobile,group,uploader,upload_id,))
		#p.daemon = True
		#p.start()
		#print('daemon started')
		ddw = dnv_dir_walk(unzip_dir,mobile,group,uploader,upload_id)
		data['file_name'] = file_name
		data['session_count'] = ddw['session_count']
		data['dns_count'] = ddw['dns_count']
		data['scan_start_time'] = ddw['scan_start']
		data['scan_end_time'] = ddw['scan_stop']
		data['scan_duration'] = ddw['scan_duration']
		data['mobile'] = mobile
		data['group'] = group
		data['uploader'] = uploader
		data['upload_id'] = upload_id
		dsh = DnvScanHistory(scan_duration=data['scan_duration'],scan_start_time=data['scan_start_time'], scan_end_time=data['scan_end_time'], mobile=data['mobile'], group=data['group'], uploader=data['uploader'], session_count=data['session_count'], upload_id=data['upload_id'])
		dsh.save()
	return render(request, 'upload/upload_scan.html', data)