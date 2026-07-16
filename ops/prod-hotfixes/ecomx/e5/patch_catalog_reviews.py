p="app/routers/catalog.py"
s=open(p).read()

s=s.replace(
"    CatalogReviewCreateIn,\n    CatalogReviewListOut,\n    CatalogReviewOut,",
"    CatalogReviewCreateIn,\n    CatalogReviewListOut,\n    CatalogReviewOut,\n    CatalogReviewSellerResponseIn,",
1)

old_list='''        out.append(
            CatalogReviewOut(
                item_id=item["item_id"],
                review_id=item["review_id"],
                rating=ddb_to_int(item["rating"]),
                title=item.get("title"),
                body=item.get("body"),
                reviewer=item.get("reviewer"),
                created_at=item["created_at"],
            )
        )'''
new_list='''        out.append(
            CatalogReviewOut(
                item_id=item["item_id"],
                review_id=item["review_id"],
                rating=ddb_to_int(item["rating"]),
                title=item.get("title"),
                body=item.get("body"),
                reviewer=item.get("reviewer"),
                created_at=item["created_at"],
                verified_purchase=bool(item.get("verified_purchase", False)),
                seller_response=item.get("seller_response"),
                seller_response_at=item.get("seller_response_at"),
            )
        )'''
assert old_list in s, "list_reviews block missing"
s=s.replace(old_list,new_list,1)

old_add='''@router.post("/items/{item_id}/reviews", response_model=CatalogReviewOut)
async def add_review(
    item_id: str,
    body: CatalogReviewCreateIn,
    ctx=Depends(require_ui_session),
):
    item_meta = _get_item_meta(item_id)
    creator_id = item_meta.get("creator_id")
    if creator_id and not can_access_creator(ctx["user_sub"], creator_id):
        raise HTTPException(status_code=403, detail="Subscription required to review.")
    review_id = body.review_id or ulid_like()
    item = {
        "PK": item_pk(item_id),
        "SK": review_sk(review_id),
        "entity": "review",
        "item_id": item_id,
        "review_id": review_id,
        "rating": int(body.rating),
        "title": body.title,
        "body": body.body,
        "reviewer": body.reviewer,
        "created_at": now_iso(),
    }
    try:
        T.catalog.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Review already exists.") from exc
        raise HTTPException(status_code=500, detail="Catalog storage error.") from exc
    return CatalogReviewOut(
        item_id=item_id,
        review_id=review_id,
        rating=item["rating"],
        title=item.get("title"),
        body=item.get("body"),
        reviewer=item.get("reviewer"),
        created_at=item["created_at"],
    )'''
new_add='''@router.post("/items/{item_id}/reviews", response_model=CatalogReviewOut)
async def add_review(
    item_id: str,
    body: CatalogReviewCreateIn,
    ctx=Depends(require_ui_session),
):
    """ECOMX-53: only a VERIFIED PURCHASER may review. The reviewer identity is
    forced from the session (user_sub) - a caller can no longer spoof another
    person via body.reviewer (it is now only a display label). Rating bounds
    (1..5) are enforced by the request model. One review per (item, author)."""
    user_sub = ctx["user_sub"]
    item_meta = _get_item_meta(item_id)
    creator_id = item_meta.get("creator_id")
    if creator_id and not can_access_creator(user_sub, creator_id):
        raise HTTPException(status_code=403, detail="Subscription required to review.")
    if creator_id and creator_id == user_sub:
        raise HTTPException(status_code=403, detail="You cannot review your own item.")
    from app.services.purchase_history import has_purchased_item
    if not has_purchased_item(user_sub, item_id):
        raise HTTPException(
            status_code=403,
            detail="Only verified purchasers can review this item.",
        )
    review_id = f"u-{user_sub}"
    verified = True
    item = {
        "PK": item_pk(item_id),
        "SK": review_sk(review_id),
        "entity": "review",
        "item_id": item_id,
        "review_id": review_id,
        "rating": max(1, min(5, int(body.rating))),
        "title": body.title,
        "body": body.body,
        "reviewer": body.reviewer or "Verified buyer",
        "reviewer_sub": user_sub,
        "verified_purchase": verified,
        "created_at": now_iso(),
    }
    try:
        T.catalog.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(PK) AND attribute_not_exists(SK)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="You have already reviewed this item.") from exc
        raise HTTPException(status_code=500, detail="Catalog storage error.") from exc

    if creator_id and creator_id != user_sub:
        try:
            from app.services.alerts import write_alert
            _stars = item["rating"]
            write_alert(
                creator_id,
                event="review_received",
                outcome="info",
                title=f"New {_stars}-star review on your item",
                details={
                    "alert_type": "review_received",
                    "item_id": item_id,
                    "review_id": review_id,
                    "rating": item["rating"],
                },
            )
        except Exception:
            logger.exception("review_received alert failed for item %s", item_id)

    return CatalogReviewOut(
        item_id=item_id,
        review_id=review_id,
        rating=item["rating"],
        title=item.get("title"),
        body=item.get("body"),
        reviewer=item.get("reviewer"),
        created_at=item["created_at"],
        verified_purchase=verified,
    )'''
assert old_add in s, "add_review block missing"
s=s.replace(old_add,new_add,1)

old_del='''@router.delete("/items/{item_id}/reviews/{review_id}")
async def delete_review(
    item_id: str,
    review_id: str,
    ctx=Depends(require_ui_session),
):
    T.catalog.delete_item(Key={"PK": item_pk(item_id), "SK": review_sk(review_id)})
    return {"ok": True}'''
new_del='''@router.delete("/items/{item_id}/reviews/{review_id}")
async def delete_review(
    item_id: str,
    review_id: str,
    ctx=Depends(require_ui_session),
):
    """ECOMX-53: only the review AUTHOR or an admin/root may delete a review."""
    user_sub = ctx["user_sub"]
    role = str(ctx.get("role") or "").lower()
    is_admin = role in ("admin", "root")
    resp = T.catalog.get_item(Key={"PK": item_pk(item_id), "SK": review_sk(review_id)})
    existing = resp.get("Item")
    if not existing:
        raise HTTPException(status_code=404, detail="Review not found.")
    author = str(existing.get("reviewer_sub") or "")
    if not is_admin and author != user_sub:
        raise HTTPException(status_code=403, detail="You can only delete your own review.")
    T.catalog.delete_item(Key={"PK": item_pk(item_id), "SK": review_sk(review_id)})
    return {"ok": True}


@router.post("/items/{item_id}/reviews/{review_id}/response", response_model=CatalogReviewOut)
async def respond_to_review(
    item_id: str,
    review_id: str,
    body: CatalogReviewSellerResponseIn,
    ctx=Depends(require_ui_session),
):
    """ECOMX-53 (E10): the item OWNER (seller) or an admin may post ONE public
    response to a review so a bad review can be addressed publicly."""
    user_sub = ctx["user_sub"]
    role = str(ctx.get("role") or "").lower()
    is_admin = role in ("admin", "root")
    item_meta = _get_item_meta(item_id)
    creator_id = item_meta.get("creator_id")
    if not is_admin and creator_id and creator_id != user_sub:
        raise HTTPException(status_code=403, detail="Only the seller can respond to a review.")
    resp = T.catalog.get_item(Key={"PK": item_pk(item_id), "SK": review_sk(review_id)})
    existing = resp.get("Item")
    if not existing:
        raise HTTPException(status_code=404, detail="Review not found.")
    ts = now_iso()
    T.catalog.update_item(
        Key={"PK": item_pk(item_id), "SK": review_sk(review_id)},
        UpdateExpression="SET seller_response = :r, seller_response_at = :t, seller_response_by = :b",
        ExpressionAttributeValues={":r": body.response, ":t": ts, ":b": user_sub},
    )
    return CatalogReviewOut(
        item_id=item_id,
        review_id=review_id,
        rating=ddb_to_int(existing["rating"]),
        title=existing.get("title"),
        body=existing.get("body"),
        reviewer=existing.get("reviewer"),
        created_at=existing["created_at"],
        verified_purchase=bool(existing.get("verified_purchase", False)),
        seller_response=body.response,
        seller_response_at=ts,
    )'''
assert old_del in s, "delete_review block missing"
s=s.replace(old_del,new_del,1)

open(p,"w").write(s)
print("catalog reviews patched")
