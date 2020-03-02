from django.urls import path
from .views import session_root, session_analyze, dnv_basic_scan, dnv_deep_scan, dnv_heuristic_scan, application, activities

urlpatterns = [
	path('', session_root, name='session_root'),
	path('analyze/', session_analyze, name='session_analyze'),
	path('dnv/basic/scan/', dnv_basic_scan, name='dnv_basic_scan'),
	path('dnv/deep/scan/', dnv_deep_scan, name='dnv_deep_scan'),
	path('dnv/heuristic/scan/', dnv_heuristic_scan, name='dnv_heuristic_scan'),
	path('dnv/application/', application, name='dnv_application'),
	path('dnv/activities/', activities, name='dnv_activities'),
]