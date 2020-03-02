from django.urls import path, include
from .views import upload_root, upload_pcap, scan_pcap, remove_pcap, remove_pcap_entry, passive_execute

urlpatterns = [
	path('', upload_root, name='upload_root'),
	path('complete/', upload_pcap, name='upload_pcap'),
	path('scan/', scan_pcap, name='scan_pcap'),
	path('remove/', remove_pcap, name='remove_pcap'),
	path('delete/entry/<str:u_id>/', remove_pcap_entry, name='remove_pcap_entry'),
	path('passive/execute/', passive_execute, name='passive_execute'),
]