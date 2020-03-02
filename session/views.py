from django.shortcuts import render
from django.db.models import Count
from django.contrib.auth.decorators import login_required
from dashboard.models import DnvSession, DnvScanHistory
# Create your views here.
@login_required
def session_root(request):
	identity = "Session Vaults"
	data = {
		'title' : identity,
		'page' : 'Network Sessions',
		'path' : ['Home',identity],
	}

	#dnv_sess = DnvSession.objects.filter(uploader=request.user).values('start_time','mobile','src_ip','src_port','dst_ip','dst_port','end_time').all().order_by('-end_time')
	sess_vaults = DnvScanHistory.objects.filter(uploader=request.user).all().order_by('-scan_end_time')
	if sess_vaults:
		data['sess_vaults'] = sess_vaults

	return render(request, 'session/session.html', data)


@login_required
def dnv_basic_scan(request):
	identity = "Session Analytics"
	data = {
		'title' : identity,
		'page' : 'Network Sessions',
		'path' : ['Home',identity],
	}
	if request.method == 'POST':
		if 'upload_id' in request.POST:
			data['upload_id'] = request.POST.get('upload_id')
			dnv_sess = DnvSession.objects.filter(uploader=request.user,upload_id=data['upload_id']).values('start_time','mobile','src_ip','src_port','dst_ip','dst_port','end_time','app_one','activity_one').all().order_by('-end_time')
			if dnv_sess:
				data['dnv_sess'] = dnv_sess
	return render(request, 'session/dnv_basic_scan.html', data)

@login_required
def dnv_deep_scan(request):
	identity = "Session Analytics"
	uni_app = []
	data = {
		'title' : identity,
		'page' : 'Network Sessions',
		'path' : ['Home',identity],
	}
	if request.method == 'POST':
		if 'upload_id' in request.POST:
			data['upload_id'] = request.POST.get('upload_id') 
			dnv_app_uni_one = DnvSession.objects.filter(uploader=request.user,upload_id=data['upload_id']).values('app_one').annotate(the_count=Count('app_one'))
			for app in dnv_app_uni_one:
				if not app['app_one']:app['app_one'] = 'Unknown'
				else:
					d = {}
					d['y'] = app['the_count']
					d['name'] = app['app_one']
					d['url'] = '/session/dnv/application/?app_name='+app['app_one']+'&upload_id='+data['upload_id']+'&from=app_one'
					uni_app.append(d)
			dev_app_uni_two = DnvSession.objects.filter(uploader=request.user,upload_id=data['upload_id']).values('app_two').annotate(the_count=Count('app_two'))
			for app in dev_app_uni_two:
				if not app['app_two']:app['app_two'] = 'Unknown'
				else:
					d = {}
					d['y'] = app['the_count']
					d['name'] = app['app_two']
					d['url'] = '/session/dnv/application/?app_name='+app['app_two']++'&upload_id='+data['upload_id']++'&from=app_two'
					uni_app.append(d)
	if uni_app:
		data['dnv_app_uni'] = sorted(uni_app, key = lambda i: i['y'],reverse=True) 
		print(data['dnv_app_uni'])

	return render(request, 'session/dnv_deep_scan.html', data)


@login_required
def dnv_heuristic_scan(request):
	identity = "Activities"
	uni_activity = []
	data = {
		'title' : identity,
		'page' : 'Track Target\'s Activities from Network',
		'path' : ['Home',identity],
	}
	if request.method == 'POST':
		if 'upload_id' in request.POST:
			data['upload_id'] = request.POST.get('upload_id') 
			dnv_act_uni_one = DnvSession.objects.filter(uploader=request.user,upload_id=data['upload_id']).values('activity_one').annotate(the_count=Count('activity_one'))
			for app in dnv_act_uni_one:
				if not app['activity_one']:app['activity_one'] = 'Unknown'
				else:
					d = {}
					d['y'] = app['the_count']
					d['name'] = app['activity_one']
					uni_activity.append(d)
			dev_act_uni_two = DnvSession.objects.filter(uploader=request.user,upload_id=data['upload_id']).values('activity_two').annotate(the_count=Count('activity_two'))
			for app in dev_act_uni_two:
				if not app['activity_two']:app['activity_two'] = 'Unknown'
				else:
					d = {}
					d['y'] = app['the_count']
					d['name'] = app['activity_two']
					uni_activity.append(d)
	if uni_activity:
		data['dnv_activity_uni'] = sorted(uni_activity, key = lambda i: i['y'],reverse=True) 
		print(data['dnv_activity_uni'])
	return render(request, 'session/dnv_heuristic_scan.html', data)

@login_required
def session_analyze(request):
	identity = "Session Analytics"
	data = {
		'title' : identity,
		'page' : 'Network Sessions',
		'path' : ['Home',identity],
	}
	if request.method == 'POST':
		if 'upload_id' in request.POST:
			data['upload_id'] = request.POST.get('upload_id')
			dnv_sess = DnvSession.objects.filter(uploader=request.user,upload_id=data['upload_id']).values('start_time','mobile','src_ip','src_port','dst_ip','dst_port','end_time').all().order_by('-end_time')
			if dnv_sess:
				data['dnv_sess'] = dnv_sess
	return render(request, 'session/session_analyze.html', data)

@login_required
def application(request):
	identity = "Applications"
	from_ = request.GET.get('from')
	app = request.GET.get('app_name')
	table_data = DnvSession.objects.filter(uploader=request.user,upload_id=request.GET.get('upload_id')).filter(app_one=app).values(from_,'start_time','mobile','src_ip','src_port','dst_ip','dst_port','end_time')
	print(table_data,"TTTTTTTTTTTTTTTTTTTTTTT")
	data = {
		'title' : identity,
		'page' : 'Target Applications',
		'path' : ['Home',identity],
		'data' : table_data
	}
	return render(request,'session/application.html', data)

@login_required
def activities(request):
	identity = "Activities"
	data = {
		'title' : identity,
		'page' : 'Target Activities',
		'path' : ['Home',identity]
	}

	return render(request,'session/activities.html', data)