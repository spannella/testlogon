import sys
path = sys.argv[1]
src = open(path).read()
import_anchor = "from app.routers.shipment_tracking import router as shipment_tracking_router  # ECOM D4\n"
import_add = ("from app.routers.seller_ship_groups import router as seller_ship_groups_router  # ECOM-SELLER (E0 reconcile)\n"
              "from app.routers.wishlist import router as wishlist_router  # ECOM E5 (E0 reconcile)\n")
mount_anchor = "    app.include_router(shipment_tracking_router)  # ECOM D4 shipment tracking\n"
mount_add = ("    app.include_router(seller_ship_groups_router)  # ECOM-SELLER seller sales/fulfilment (E0)\n"
             "    app.include_router(wishlist_router)  # ECOM E5 wishlist (E0)\n")
if "seller_ship_groups_router" in src:
    print("ALREADY MOUNTED -- skipping"); sys.exit(0)
assert import_anchor in src, "import anchor not found"
assert mount_anchor in src, "mount anchor not found"
src = src.replace(import_anchor, import_anchor + import_add, 1)
src = src.replace(mount_anchor, mount_anchor + mount_add, 1)
open(path, "w").write(src)
print("MOUNTED OK")
