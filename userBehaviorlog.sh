LOGDIR="/data/apache-tomcat-7.0.57/logs/actsctrl"
cd /data/work/actsctrLogAnalyse
CURDIR=`pwd`
YESTDAY=`date -d '-1 day' +%Y-%m-%d`
TODAY=`date +%Y-%m-%d`
#源日志文件
LOGFILE="$LOGDIR/common_$YESTDAY.log"
#汇总日志
YESTSUMLOGFILE="$CURDIR/Log/behavior_common_$YESTDAY.log"

#汇总日志文件操作
rm -f $YESTSUMLOGFILE
#echo "cp $LOGFILE $SUMMARYLOGFILE"
#cp -f $LOGFILE $SUMMARYLOGFILE
for i in {1..3}
do
	LOGHOST="actsctrl0$i.*-inc.cn"
	TEMPLOGFILE="$CURDIR/Log/actsctrl0$i$YESTDAY.log"
	echo "scp log from $LOGHOST:$LOGFILE to $TEMPLOGFILE"
	scp root@$LOGHOST:$LOGFILE $TEMPLOGFILE

	cat $TEMPLOGFILE >> $YESTSUMLOGFILE
	rm -f $TEMPLOGFILE
done

echo "begin Analyse ..."

# 用户行为日志统计
BIHAVIORLOGFILE="$YESTSUMLOGFILE-behavior"
rm -f $BIHAVIORLOGFILE
cat $YESTSUMLOGFILE |grep "request string" |cut -d: -f3 >> $BIHAVIORLOGFILE
# awk '{if ($1 ~/^1/) {$1=null; print $0;} else print }'
rm -f $YESTSUMLOGFILE
