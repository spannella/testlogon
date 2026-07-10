import boto3

B = "testlogon-apk-749211675678"
KEY = "demos/v3-ecommerce.mp4"
SRC = "/tmp/v3-ecommerce.mp4"

s3 = boto3.client("s3", region_name="us-east-2")
s3.upload_file(SRC, B, KEY, ExtraArgs={"ContentType": "video/mp4"})
url = s3.generate_presigned_url("get_object", Params={"Bucket": B, "Key": KEY}, ExpiresIn=604800)
print("UPLOADED", KEY)
print("PRESIGNED_URL", url)

body = f"""The re-recorded TestLogon V3 ecommerce demo (seller fulfilment) is ready.

What changed in this build (seller-fulfilment polish, P1 + P2):

P1 - Sold-push now DEEP-LINKS to the exact sale.
   Tapping the "You sold ..." system-tray push opens the app DIRECTLY to that
   sale's detail (item + buyer shipping address + fulfilment controls) instead
   of the app home. The FCM data payload now carries the alert action_url
   (generic for any alert), and the push tap reuses the same in-app resolver the
   Alerts row uses to route to the sale.

P2 - Sold-push is ON BY DEFAULT (opt-out, not opt-in).
   A seller receives the "you sold it" push without manually enabling any push
   preference. shop_item_sold (and other transactional order/payment events) are
   default-on; a seller can still disable it.

The V3 demo (62s) is a clean real end-to-end on a Galaxy A15 against the live
backend: buyer buys -> seller gets the push (no opt-in) -> tap the push -> opens
the exact sale -> real item + buyer address (Columbus OH) -> mark shipped
(tracking 1Z999AA10123456784 / UPS) -> Status: shipped.

Watch (7-day link): {url}

Verified: in-process on prod 13/13 (default-on + disable-able + FCM data carries
action_url, explicitly and resolved-from-alert-row); on-device the real FCM push
arrived without enabling prefs and its tap opened the exact sale. App build
BUILD_EXIT=0; installed + launch-clean on both phones (Galaxy A15 + Pixel 7a).
"""

ses = boto3.client("ses", region_name="us-east-1")
r = ses.send_email(
    Source="TestLogon <app@bitbazaar.cc>",
    Destination={"ToAddresses": ["spannella@gmail.com"]},
    Message={
        "Subject": {"Data": "Re-recorded TestLogon V3 ecommerce demo - sold-push deep-link + default-on"},
        "Body": {"Text": {"Data": body}},
    },
)
print("SES_MESSAGE_ID", r["MessageId"])
print("EMAIL_SENT spannella@gmail.com")
