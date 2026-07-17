p="app/models.py"
s=open(p).read()
old='''class EarningsBreakdown(BaseModel):
    subscriptions: int = 0
    tips: int = 0
    unlocks: int = 0
    vod_purchases: int = 0
    other: int = 0'''
new='''class EarningsBreakdown(BaseModel):
    subscriptions: int = 0
    tips: int = 0
    unlocks: int = 0
    vod_purchases: int = 0
    # ECOMX-50: shop + live-commerce revenue as distinct earnings buckets
    # (previously collapsed into "other").
    shop_sales: int = 0
    live_commerce: int = 0
    other: int = 0'''
assert old in s
s=s.replace(old,new)
open(p,"w").write(s)
print("models.py EarningsBreakdown patched")
