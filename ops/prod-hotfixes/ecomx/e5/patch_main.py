p="app/main.py"
s=open(p).read()
old_imp="from app.routers.seller_ship_groups import router as seller_ship_groups_router  # ECOM-SELLER (E0 reconcile)"
new_imp=old_imp+"\nfrom app.routers.seller_ship_groups import analytics_router as seller_analytics_router  # ECOMX-51 (E5)"
assert old_imp in s
s=s.replace(old_imp,new_imp,1)
old_mnt="    app.include_router(seller_ship_groups_router)  # ECOM-SELLER seller sales/fulfilment (E0)"
new_mnt=old_mnt+"\n    app.include_router(seller_analytics_router)  # ECOMX-51 seller sales analytics (E5)"
assert old_mnt in s
s=s.replace(old_mnt,new_mnt,1)
open(p,"w").write(s)
print("main.py mounted seller_analytics_router")
