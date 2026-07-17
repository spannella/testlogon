p = "app/models.py"
s = open(p).read()
assert "CreatorDisputeRespondIn" not in s, "already patched"

old_resolve = '''class DisputeResolveIn(BaseModel):
    # DISP-013: user-track outcomes drive the reversal dispatcher; legacy
    # won|lost|accepted still accepted + mapped for the old admin path.
    resolution: str = Field(pattern="^(refunded|partial|denied|won|lost|accepted)$")
    override_amount_cents: Optional[int] = Field(default=None, ge=1)
    notes: Optional[str] = Field(default=None, max_length=2000)'''
new_resolve = '''class DisputeResolveIn(BaseModel):
    # DISP-013: user-track outcomes drive the reversal dispatcher; legacy
    # won|lost|accepted still accepted + mapped for the old admin path.
    resolution: str = Field(pattern="^(refunded|partial|denied|won|lost|accepted)$")
    override_amount_cents: Optional[int] = Field(default=None, ge=1)
    notes: Optional[str] = Field(default=None, max_length=2000)
    # DISP-022: a money-moving resolve above the dual-approval threshold requires
    # a second, distinct PAYMENT_DISPUTES admin id (validated server-side; a
    # fabricated/self/non-scoped id is rejected).
    second_approver_admin_user_id: Optional[str] = Field(default=None, max_length=200)


class CreatorDisputeRespondIn(BaseModel):
    """DISP-021: the creator/seller rebuts a dispute within the response window."""
    response_text: str = Field(min_length=1, max_length=5000)
    evidence_files: Optional[List[str]] = None'''

assert old_resolve in s, "resolve anchor not found"
s = s.replace(old_resolve, new_resolve, 1)
open(p, "w").write(s)
print("models.py patched OK")
