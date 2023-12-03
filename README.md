# :rocket: AWS-VPC-Flow-Logs Ingestion Into SnowFlake 
VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. Flow logs can help you with a number of tasks, such as:

Monitoring the traffic that is reaching your instance
Determining the direction of the traffic to and from the network interfaces
Analyzing properties such as IP addresses, ports, protocol and total packets sent without the overhead of taking packet captures
Flow log data is collected outside of the path of your network traffic, and therefore does not affect network throughput or latency. You can create or delete flow logs without any risk of impact to network performance.

This quickstart is a guide for ingestion AWS VPC Flowlogs into Snowflake. It demonstrates configuration of VPC flowlogs on AWS, ingestion using an external stage with Snowpipe and sample queries for CSPM and threat detection.
## :arrow_right: Prerequisites
**:black_small_square: AWS user with permission to create and manage IAM policies and roles**

**:black_small_square: Snowflake user with permission to create tables, stages and storage integrations as well as setup snowpipe.**

**:black_small_square: An S3 Bucket**

## :jigsaw: Architecture
![image](https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/18814baa-124b-4317-b209-e81df30f38d7)

## Enable VPC Flow Logs and Push to S3
From the VPC page in the AWS console, select the VPC you wish to enable flow logs on. Select the "Flow Logs" tab and press "Create flow log"
![image](https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/5aa033e2-5c52-497f-b8ea-99c796c3a0b8)

Configure VPC flow logs as desired. Use the following settings:

**Destination:** Send to an Amazon S3 Bucket

**S3 Bucket ARN:** S3 Bucket ARN and prefix of existing bucket ( or press the "create s3 bucket" link to create a new one)

**Log file format:** Parquet

![image](https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/35069326-aecc-4242-82c2-075ea55f06b1)

**1.Create one IAM Role and Paste ARN in the below code.**

**2.Create one S3 Bucket and Paste It's URI in the code below**

## Create a storage integration in Snowflake

```
create STORAGE INTEGRATION s3_int_vpc_flow
  TYPE = EXTERNAL_STAGE
  STORAGE_PROVIDER = S3
  ENABLED = TRUE
  STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::<AWS_ACCOUNT_NUMBER>:role/<RoleName>'
  STORAGE_ALLOWED_LOCATIONS = ('s3://<BUCKET_NAME>/<PREFIX>/');

DESC INTEGRATION s3_int_vpc_flow;
```
Take note of **STORAGE_AWS_IAM_USER_ARN and STORAGE_AWS_EXTERNAL_ID**

![image](https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/acc53634-2665-46a5-8326-f2205064d34f)

Open up Cloudshell in the AWS console by pressing the aws cloudshell icon icon on the right side of the top navigation bar or run the following commands in your terminal once configured to use the AWS CLI.

Export the following variables, replacing the values with your own.
```
export BUCKET_NAME='<BUCKET_NAME>'
export PREFIX='<PREFIX>' # no leading or trailing slashes
export ROLE_NAME='<ROLE_NAME>'
export STORAGE_AWS_IAM_USER_ARN='<STORAGE_AWS_IAM_USER_ARN>'
export STORAGE_AWS_EXTERNAL_ID='<STORAGE_AWS_EXTERNAL_ID>'
```
**Open your IAM role and edit Trust (Trust relationships) Policy and paste below code in it.**
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "AWS": "'${STORAGE_AWS_IAM_USER_ARN}'"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "'${STORAGE_AWS_EXTERNAL_ID}'"
                }
            }
        }
    ]
}
```
**Now We will require to create an Inline Policy for our role**
<img width="960" alt="image" src="https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/57e096a1-d815-4e74-ba49-55f2026e22ac">

**Create Inline Policy and Paste below code there.**
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
              "s3:PutObject",
              "s3:GetObject",
              "s3:GetObjectVersion",
              "s3:DeleteObject",
              "s3:DeleteObjectVersion"
            ],
            "Resource": "arn:aws:s3:::'${BUCKET_NAME}'/'${PREFIX}'/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation"
            ],
            "Resource": "arn:aws:s3:::'${BUCKET_NAME}'",
            "Condition": {
                "StringLike": {
                    "s3:prefix": [
                        "'${PREFIX}'/*"
                    ]
                }
            }
        }
    ]
}
```
## Prepare Snowflake to receive data
This project will requires a warehouse to perform computation and ingestion. 
I recommend creating a separate warehouse for security related analytics if one does not exist. 
The following will create a medium sized single cluster warehouse that suspends after 5 minutes of inactivity. 
For production workloads a larger warehouse will likely be required.
```
create warehouse security_quickstart with 
  WAREHOUSE_SIZE = MEDIUM 
  AUTO_SUSPEND = 300;
```
**Create External Stage using the storage integration. Make sure you include the trailing slash if using a prefix.**
```
create stage vpc_flow_stage
  url = 's3://<BUCKET_NAME>/<PREFIX>/'
  storage_integration = s3_int_vpc_flow
;
```
**Check if snowflake can list S3 files**
```
list @vpc_flow_stage;
```
![image](https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/a78af9c1-7ba9-4df5-a2c2-544d61e63e0e)
```
create table public.vpc_flow(
  record VARIANT
);
```
**Test Injection from External Stage**
```
copy into public.vpc_flow
  from @vpc_flow_stage
  file_format = (type = parquet);
```
![image](https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/b462c859-b1d9-4fa2-be92-88f8ff87293a)

**Select data**
```
select * from public.vpc_flow limit 10;
```
![image](https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/1f6f1b30-2800-492f-a8f0-966623479411)

## Setup Snowpipe for continuous loading
**Configure the Snowflake snowpipe**
```
create pipe public.vpc_flow_pipe auto_ingest=true as
  copy into public.vpc_flow
  from @public.vpc_flow_stage
  file_format = (type = parquet)
;
```
**Show pipe to retrieve SQS queue ARN**
```
show pipes;
```
**Setup S3 bucket  Target Bucket -> Open property -> Select "Create Event notification"**

![image](https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/8b3424f8-55e8-4eb8-a867-c72fe853f8fe)

**:black_small_square: Name: Name of the event notification (e.g. Auto-ingest Snowflake).**

**:black_small_square: Prefix(Optional) : if you receive notifications only when files are added to a specific folder (for example, logs/).**

**:black_small_square: Events: Select the ObjectCreate (All) option.**

**:black_small_square: Send to: Select "SQS Queue" from the dropdown list.**

**:black_small_square: SQS: Select "Add SQS queue ARN" from the dropdown list.**

**:black_small_square: SQS queue ARN: Paste the SQS queue name from the SHOW PIPES output.**
![image](https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/d07b68a5-23e3-4404-9f2a-2613fc7d6883)
![image](https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/a847a37f-2873-4329-858f-adcb41ff17b2)
![image](https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/1bf4b5f6-a472-48d0-bb85-589093622c5b)

**Refresh Snowpipe to retrieve unloaded file and run select if unloaded data should be loaded**
```
alter pipe vpc_flow_pipe refresh;
select * from public.vpc_flow;
```
**You can confirm also if snowpipe worked properly**
```
SELECT *
FROM TABLE(SNOWFLAKE.INFORMATION_SCHEMA.PIPE_USAGE_HISTORY(
  DATE_RANGE_START => DATEADD('day', -14, CURRENT_DATE()),
  DATE_RANGE_END => CURRENT_DATE(),
  PIPE_NAME => 'public.vpc_flow_pipe'
));
```
## Create a view to better query data
```
create view vpc_flow_view as
select 
    record:account_id::varchar(16) as account_id,
    record:action::varchar(16) as action,
    record:bytes::integer as bytes,
    record:dstaddr::varchar(128) as dstaddr,
    record:dstport::integer as dstport,
    record:end::TIMESTAMP as "END",
    record:interface_id::varchar(32) as interface_id,
    record:log_status::varchar(8) as log_status,
    record:packets::integer as packets,
    record:protocol::integer as protocol,
    record:srcaddr::varchar(128) as srcaddr,
    record:srcport::integer as srcport,
    record:start::TIMESTAMP as "START",
    record:version::varchar(8) as version
from public.vpc_flow;
```
**Preview the data**

```
select * from vpc_flow_view limit 10;
```
![image](https://github.com/King4424/AWS-VPC-Flow-Logs-Ingestion/assets/121480992/a894d49a-4122-4cdc-b531-5c7aa1420e60)

## Query the data
```
CREATE OR REPLACE FUNCTION ipv4_is_internal(ip varchar)
  RETURNS Boolean
  AS
  $$
    (parse_ip(ip,'INET'):ipv4 between (167772160) AND (184549375)) OR 
    (parse_ip(ip,'INET'):ipv4 between (2886729728) AND (2887778303))OR 
    (parse_ip(ip,'INET'):ipv4 between (3232235520) AND (3232301055))
  $$
  ;
  
-- Administrative traffic from public internet in past 30 days

(select distinct srcaddr as internal_addr,dstaddr as external_addr, srcport as port from vpc_flow_view where "START" > dateadd(day, -30, current_date()) and action = 'ACCEPT' and srcport in (22,3389) and ipv4_is_internal(internal_addr)) 
union all 
(select distinct dstaddr as internal_addr,srcaddr as external_addr, dstport as port from vpc_flow_view where "START" > dateadd(day, -30, current_date()) and action = 'ACCEPT' and dstport in (22,3389) and ipv4_is_internal(internal_addr));


-- Biggest talkers by destination in past 30 days
select dstaddr,sum(bytes) as total_bytes from vpc_flow_view where "START" > dateadd(day, -30, current_date()) and action = 'ACCEPT' group by dstaddr order by total_bytes desc limit 10;

-- Biggest talkers by source in past 30 days
select srcaddr,sum(bytes) as total_bytes from vpc_flow_view where "START" > dateadd(day, -30, current_date()) and action = 'ACCEPT' group by srcaddr order by total_bytes desc limit 10;

-- Biggest talkers by ENI in past 30 days
select interface_id,sum(bytes) as total_bytes from vpc_flow_view where "START" > dateadd(day, -30, current_date()) and action = 'ACCEPT' group by interface_id order by total_bytes desc limit 10;
```
## Conclusion & next steps
**Having completed this quickstart we have successfully:**

1.Enabled VPC flow logs

2.Created and configured an external stage using S3

3.Ingested VPC flow logs into snowflake

4.Created and configured a pipeline to automatically load data

5.Created a view to better explore and query VPC flow logs

6.Explored sample queries to get insights out of your flow logs

## :sun_behind_small_cloud: THANK YOU AND WELCOME !!

## :snowflake: Subscribe To My YouTube Channel "SnowOps_Hub"

**https://youtu.be/uOBJ-vzA3UY**








