p="app/models.py"
s=open(p).read()
old='''class CatalogReviewCreateIn(BaseModel):
    review_id: Optional[str] = None
    rating: int = Field(ge=1, le=5)
    title: Optional[str] = None
    body: Optional[str] = None
    reviewer: Optional[str] = None


class CatalogReviewOut(BaseModel):
    item_id: str
    review_id: str
    rating: int
    title: Optional[str] = None
    body: Optional[str] = None
    reviewer: Optional[str] = None
    created_at: str'''
new='''class CatalogReviewCreateIn(BaseModel):
    review_id: Optional[str] = None
    rating: int = Field(ge=1, le=5)
    title: Optional[str] = None
    body: Optional[str] = None
    # ECOMX-53: reviewer display name is caller-supplied ONLY as a label; the
    # authoritative author identity is forced from the session user_sub server
    # side (see add_review). A spoofed ``reviewer`` can no longer impersonate.
    reviewer: Optional[str] = None


class CatalogReviewSellerResponseIn(BaseModel):
    # ECOMX-53 (E10): a seller/owner public reply to a review.
    response: str = Field(min_length=1, max_length=2000)


class CatalogReviewOut(BaseModel):
    item_id: str
    review_id: str
    rating: int
    title: Optional[str] = None
    body: Optional[str] = None
    reviewer: Optional[str] = None
    created_at: str
    # ECOMX-53: verified-purchase badge + optional seller response.
    verified_purchase: bool = False
    seller_response: Optional[str] = None
    seller_response_at: Optional[str] = None'''
assert old in s
s=s.replace(old,new)
open(p,"w").write(s)
print("review models patched")
