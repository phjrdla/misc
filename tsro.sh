#!/usr/bin/ksh
#
# table platform_id <-> Operatng system
# select * from v$transportable_platform; 
#

#cnx='system/Qmx0225_nnzdev'
cnx='/ as sysdba'

tablespaces=$(sqlplus -s $cnx <<!
set timing off
set pages 0
set lines 200
set trimspool on
set heading off
set feedback off
spool tsro.cmd
select 'alter tablespace '||tablespace_name||' READ ONLY;'
from dba_tablespaces
where  tablespace_name not in ('SYSTEM','SYSAUX','TEMP','UNDOTBS1')
order by tablespace_name
/
spool off
!
)

cat tsro.cmd
