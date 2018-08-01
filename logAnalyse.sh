LOGDIR="/data/apache-tomcat-7.0.57/logs/actsctrl"
cd /data/work/actsctrLogAnalyse
CURDIR=`pwd`
YESTDAY=`date -d '-1 day' +%Y-%m-%d`
TODAY=`date +%Y-%m-%d`
#源日志文件
LOGFILE="$LOGDIR/common_$TODAY.log"
#汇总日志
YESTSUMLOGFILE="$CURDIR/Log/common_$YESTDAY.log"
SUMMARYLOGFILE="$CURDIR/Log/common_$TODAY.log"
#分析后结果文件
OUTFILE="$CURDIR/result/forbid_$TODAY.log"
HISTORYOUTFILE="$CURDIR/result/forbid_$TODAY.log.old"
echo $LOGFILE $OUTFILE

#汇总日志文件操作
rm -f $YESTSUMLOGFILE
rm -f $SUMMARYLOGFILE
#echo "cp $LOGFILE $SUMMARYLOGFILE"
#cp -f $LOGFILE $SUMMARYLOGFILE
for i in {1..3}
do
        LOGHOST="actsctrl0$i.edaijia-inc.cn"
        TEMPLOGFILE="$CURDIR/Log/actsctrl0$i$TODAY.log"
        echo "scp log from $LOGHOST:$LOGFILE to $TEMPLOGFILE"
        scp root@$LOGHOST:$LOGFILE $TEMPLOGFILE

        cat $TEMPLOGFILE >> $SUMMARYLOGFILE
        rm -f $TEMPLOGFILE
done

echo "begin Analyse ..."
#保存上一次的结果
mv -f $OUTFILE $HISTORYOUTFILE

# 用户行为日志统计
#BIHAVIORLOGFILE="behavior_$SUMMARYLOGFILE"
#cat $SUMMARYLOGFILE |grep "request string" |cut -d: -f3 >> $BIHAVIORLOGFILE

#生成新结果
cat $SUMMARYLOGFILE|grep "\"code\":4006"| awk '{print $4,$6,$8,$10,$NF }' | awk -F "," '{print $1,$2,$3,$4,$5}' | awk -F "]" '{print $1,$2}'|awk -F "[" '{print $1,$2}'| awk '{print $1,$2,$3,$5,$4}' | sort | uniq -c | sort -nr >> $OUTFILE

# send mail
echo "send mail"
python sendmail.py -l $OUTFILE
