cd /data/work/actsctrLogAnalyse
CURDIR=`pwd`
YESTFORBIDLOGFILE="$CURDIR/result/forbid_`date -d '-1 day' +%Y-%m-%d`.log"
echo $YESTFORBIDLOGFILE
YESTDAY=`date -d '-1 day' +%Y%m%d`
TODAY=`date +%Y%m%d`
CORDERMULTI_IP_FILE="$CURDIR/result/c_order_multi_ip_$YESTDAY"
CORDERMULTI_IP_ACCESS_LOG="$CURDIR/Log/c_order_multi_ip_access_log_$YESTDAY"
CORDERMULTI_PHONE="$CURDIR/result/c_order_multi_phone_$YESTDAY"

#昨天报警中被封禁大于100次的ip,用于判断是否为运营商出口ip.此ip上操作的用户。
TOP_FORBID_IP_FILE="$CURDIR/result/top_forbid_ip_$YESTDAY"
TOP_FORBID_IP_ACCESS_LOG="$CURDIR/Log/top_forbid_ip_access_log_$YESTDAY"
TOP_FORBID_IP_USER="$CURDIR/result/top_forbid_ip_user_$YESTDAY"

echo $YESTDAY,$TODAY
rm -f $CORDERMULTI_IP_FILE
cat $YESTFORBIDLOGFILE |grep "edai*jia c_order_multi ip ip-rule" |awk '{if($1 >100) {print $6}}' >>$CORDERMULTI_IP_FILE
rm -f "$CURDIR/Log/access0*.log"
#rm -f $CORDERMULTI_IP_ACCESS_LOG


rm -f $TOP_FORBID_IP_FILE;
echo $TOP_FORBID_IP_FILE
cat $YESTFORBIDLOGFILE | grep " ip "| awk '{if($1 >100) {print $6}}'|sort -u >> $TOP_FORBID_IP_FILE

for i in {1..3}
do
  echo $i;
  accessfile="$CURDIR/Log/access0$i$YESTDAY.log";
  scp root@actsctrl0$i:/data/logs/nginx/access_$YESTDAY.log $accessfile ;
  echo $accessfile;
  cat $accessfile |grep c_prelogin |grep phone |awk -F "phone|ip" '{print substr($2,24,15)" "substr($3,24,11)}'|awk -F '[ %]' '{print $1,$NF}' >> $CURDIR/Log/c_prelogin_$YESTDAY
  for ip in `cat $CORDERMULTI_IP_FILE`
  do
    echo $ip,$accessfile;
    cat $accessfile|grep $ip >>$CORDERMULTI_IP_ACCESS_LOG;
  done

  #统计所有被报警ip上的用户。
  for ip in `cat $TOP_FORBID_IP_FILE`
  do
    echo $ip, $accessfile;
    cat $accessfile|grep $ip >> $TOP_FORBID_IP_ACCESS_LOG;
  done
done
