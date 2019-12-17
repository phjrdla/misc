#!/usr/bin/ksh
#
# table platform_id <-> Operatng system
# select * from v$transportable_platform; 
#

tablespaces=$(sqlplus -s system/Qmx0225_nnzdev <<!
set pages 0
set lines 200
set trimspool on
set heading off
set feedback off
select tablespace_name
from dba_tablespaces
where  tablespace_name not in ('SYSTEM','SYSAUX','TEMP','UNDOTBS1')
order by 1
/
!
)

(( i = 0 ))
for ts in $tablespaces
do
  (( i += 1 ))
  print "C'est la cochonnerie $i : $ts"
  if (( i == 1 ))
  then  
    ts_list="$ts"
  else
    ts_list="$ts_list,$ts"
  fi
done
print $ts_list
echo $ts_list > tablespaces.txt

cat <<!  > myfppties.txt
tablespaces=$ts_list
platformid=2
src_scratch_location=/nfs_oracle/src_backups/
dest_datafile_location=/oradata/DASS
dest_scratch_location=/nfs_oracle/src_backups/
usermantransport=1
!
