from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import DnvSession
from django.db.models import Count
# Create your views here.
@login_required
def dashboard(request):
	identity = "Home"
	data = {
		'title' : identity,
		'page' : 'Deep Network Visualizer',
		'path' : [identity],
		'db_status' : True#dnv_db_status(connections)
	}
	uni_app = []
	uni_activity = []
	application_data = DnvSession.objects.values('app_one').annotate(the_count=Count('app_one'))
	for app in application_data:
		if not app['app_one']:app['app_one'] = 'Unknown'
		else:
			d = {}
			d['y'] = app['the_count']
			d['name'] = app['app_one']
			# d['url'] = '/session/dnv/application/?app_name='+app['app_one']+'&upload_id='+data['upload_id']+'&from=app_one'
			uni_app.append(d)
	if uni_app:
		data['application_data'] = sorted(uni_app, key = lambda i: i['y'],reverse=True)
		# data['application_data'] = uni_app 
	activity_data = DnvSession.objects.values('activity_one').annotate(the_count=Count('activity_one'))
	for app in activity_data:
		if not app['activity_one']:app['activity_one'] = 'Unknown'
		else:
			d = {}
			d['y'] = app['the_count']
			d['name'] = app['activity_one']
			uni_activity.append(d)
	if uni_activity:
		data['activity_data'] = sorted(uni_activity, key = lambda i: i['y'],reverse=True)
		# data['activity_data'] = uni_activity
	
	if data['db_status']:
		pass
	if request.method=="POST":
		mobile_number = request.POST.get('mobile_search')
		source_ip = request.POST.get('ip_search')
		if (mobile_number):
			summary = DnvSession.objects.filter(mobile=mobile_number).values('start_time','mobile','src_ip','src_port','dst_ip','dst_port','end_time','app_one','activity_one')
			data['summary'] = summary
			data['value_by'] = mobile_number
		else:
			summary = DnvSession.objects.filter(src_ip=source_ip).values('start_time','mobile','src_ip','src_port','dst_ip','dst_port','end_time','app_one','activity_one')
			data['summary'] = summary
			data['value_by'] = source_ip
		# data['dashboard_upper_tabs'] = [
		# 	{'name':'WEB LINKS','color':'lazur-bg','count':100,'icon':'fa fa-globe fa-5x','url':'/'},
		# 	{'name':'DNS','color':'lazur-bg','count':100,'icon':'fa fa-database fa-5x','url':'/'},
		# 	{'name':'DEVICES','color':'lazur-bg','count':100,'icon':'fa fa-mobile fa-5x','url':'/'},
		# 	{'name':'EMAIL','color':'lazur-bg','count':100,'icon':'fa fa-envelope fa-5x','url':'/'},
		# 	{'name':'PASSWORD','color':'lazur-bg','count':100,'icon':'fa fa-key fa-5x','url':'/'},
		# 	{'name':'ATTACHMENTS','color':'lazur-bg','count':100,'icon':'fa fa-copy fa-5x','url':'/'},
		# 	{'name':'IMAGES','color':'lazur-bg','count':100,'icon':'fa fa-image fa-5x','url':'/'},
		# 	{'name':'VIDEOS','color':'lazur-bg','count':100,'icon':'fa fa-image fa-5x','url':'/'},
		# 	{'name':'VOIP','color':'lazur-bg','count':100,'icon':'fa fa-phone fa-5x','url':'/'},
		# 	{'name':'USER AGENTS','color':'lazur-bg','count':100,'icon':'fa fa-desktop fa-5x','url':'/'},
		# 	{'name':'CHATS','color':'lazur-bg','count':100,'icon':'fa fa-android fa-5x','url':'/'},
		# 	{'name':'APP','color':'lazur-bg','count':100,'icon':'fa fa-android fa-5x','url':'/'},
		# ]
	print(data)
	return render(request, 'dashboard/dashboard.html', data)