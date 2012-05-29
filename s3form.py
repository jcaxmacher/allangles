from datetime import datetime,timedelta
AWS_ACCESS_KEY = "AKIAIOVXMOUEL26POEBQ"
AWS_SECRET_KEY = "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"

def generate_post_form(bucket_name, key, post_key, file_id, file_name, content_type, timeout=timedelta(seconds=600)):
    import hmac
    from hashlib import sha1
    policy = """
    {
        "expiration": "%(expires)s",
        "conditions": [
            {"bucket":"%(bucket)s"},
            ["eq","$key","%(key)s"],
            {"acl":"private"},
            {"x-amz-meta-content_type":"%(content_type)s"},
            {"x-amz-meta-file_name":"%(file_name)s"},
            {"x-amz-meta-post_key":"%(post_key)s"},
            {"x-amz-meta-file_id":"%(file_id)s"},
            {"success_action_status":"200"}
        ]
    }
    """
    policy = policy % {
        "expires":(datetime.utcnow()+timeout).strftime("%Y-%m-%dT%H:%M:%SZ"), # This has to be formatted this way
        "bucket": bucket_name, # the name of your bucket
        "key": key, # this is the S3 key where the posted file will be stored
        "post_key": post_key, # custom properties begin here
        "file_id":file_id,
        "file_name": file_name,
        "content_type": content_type,
    }
    encoded = policy.encode('utf-8').encode('base64').replace("\n","") # Here we base64 encode a UTF-8 version of our policy.  Make sure there are no new lines, Amazon doesn't like them.
    return ("http://allangles.s3.amazonaws.com/",
          {"policy":encoded,
           "signature":hmac.new(AWS_SECRET_KEY,encoded,sha1).digest().encode("base64").replace("\n",""), # Generate the policy signature using our Amazon Secret Key
           "key": key,
           "AWSAccessKeyId": AWS_ACCESS_KEY, # Obviously the Amazon Access Key
           "acl":"private",
           "x-amz-meta-post_key":post_key,
           "x-amz-meta-file_id":file_id,
           "x-amz-meta-file_name": file_name,
           "x-amz-meta-content_type": content_type,
           "success_action_status":"200",
          })


policy_template = """
{"expiration": "2019-01-01T00:00:00Z",
  "conditions": [ 
    {"bucket": "allangles"}, 
    ["starts-with", "$key", "uploads/"],
    {"acl": "private"},
    {"success_action_redirect": "http://4edj.localtunnel.com"},
    ["starts-with", "$Content-Type", "image/"],
    ["content-length-range", 0, 1048576]
  ]
}
"""


