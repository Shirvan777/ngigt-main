from unicodedata import name
from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
from . import views

urlpatterns =  [
    path('', views.index,name='index'),
    path('login',views.login,name='login'),
    path('logout',views.logout,name='logout'),
    path('subdomain_finder',views.subdomain_finder,name='subdomain_finder'),
    path('dns_search',views.dns_search,name='dns_search'),
    path('whois_search',views.whois_search,name='whois_search'),
    path('netcraft',views.netcraft,name='netcraft'),
    path('about_creators',views.about_creators,name='about_creators'),
    path('download',views.download,name='download'),

] + static(settings.MEDIA_URL,document_root = settings.MEDIA_ROOT)


handler404 = 'webtools.views.custom_page_not_found_view'
handler500 = 'webtools.views.custom_500_error'