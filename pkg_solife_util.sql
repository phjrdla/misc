/*
Package used
  to ensure that all user sessions are killed on an Oracle instance except the one specified
  to enable or disable restricted mode on an Oracle instance
  
Sessions with 'restricted session' can log in

author  : bip
date    : 22-MAR-18
date    : 29-MAR-18 move alter system ahaed of killing sessions
*/
create or replace package solife_util as
  procedure enable_restricted ( grantTo all_users.username%type, doit boolean default false ) ;
  procedure disable_restricted ( revokeFrom all_users.username%type, doit boolean default false );
end solife_util;
/
create or replace package body solife_util as
  procedure display_mode(doit boolean) is
  begin
    if doit then
      dbms_output.put_line(chr(10)||'***************** LIVE *************************');
    else
      dbms_output.put_line(chr(10)||'***************** SIMULATION *************************');
    end if;
  end display_mode;

  procedure enable_restricted ( grantTo all_users.username%type, doit boolean default false ) is
    /*
    Kills all user sessions except SYS DBSNMP OPCON OPCONAP
    Enables restricted mode on database
    */
    c_username v$session.username%type; 
    c_sid      v$session.sid%type; 
    c_serial   v$session.serial#%type;
    c_status   v$session.status%type;
    c_taddr    v$session.taddr%type;
    cmd        varchar2(80);
    msg        varchar2(80);
    username   varchar2(30);
    cnt        integer;
    sessn      integer := 0;
    sesskilled integer := 0;
    v_code     NUMBER;
    v_errm     VARCHAR2(64);
  
    CURSOR c_sessions is 
      SELECT username, sid, serial#, status, taddr
        FROM v$session
       WHERE username not in ('SYS','SYSTEM','DBSNMP','OPCON','OPCONAP')
       ORDER BY USERNAME; 
      
    begin
      -- Check that user <<grantTo>> exists in db
      dbms_output.put_line('Check that user '||grantTo||' exists in database');
      execute immediate 'select 1 from all_users where username = upper(:grantTo)' into cnt using grantTo;
      
      -- Grant 'restricted session' to  user <<grantTo>>
      cmd := 'GRANT RESTRICTED SESSION to '||grantTo;
      display_mode(doit);
      dbms_output.put_line(cmd);
      if doit then
        execute immediate cmd;
      end if;
     
      -- Current number of sessions 
      execute immediate 'select count(1) from v$session ' into cnt;
      dbms_output.put_line('Current number of sessions is '||to_char(cnt));
      
    -- Restrict access to database
      cmd := 'ALTER SYSTEM ENABLE RESTRICTED SESSION';
      display_mode(doit);
      dbms_output.put_line(cmd);
      if doit then
        execute immediate cmd;
        msg := 'Restricted mode is now enabled';
        dbms_output.put_line(msg);
      end if;
      
      -- List and kill sessions
      OPEN c_sessions; 
        LOOP 
          FETCH c_sessions into c_username, c_sid, c_serial, c_status, c_taddr; 
          EXIT WHEN c_sessions%notfound; 
        
          -- Session being processed
          sessn := sessn + 1;
          dbms_output.put_line('Session '||to_char(sessn)||' : User is '||c_username||' session status is '||c_status );
       
          -- Warning if session involved in a transaction
          if  c_taddr is not null then 
            dbms_output.put_line('A transaction is still running, will complete before session is terminated');
          else
            dbms_output.put_line('Session is clean');
          end if;
      
          cmd := 'alter system kill session '||''''||to_char(c_sid)||','||to_char(c_serial)||''' immediate';
          display_mode(doit);
          dbms_output.put_line(cmd);
          if doit then 
            ------------------------------------------------------------
            begin 
              execute immediate cmd;
              -- handle sessions already gone
              exception
                when others then
                  if SQLCODE = -30 then
                    continue; -- suppreses ORA-00030 exception
                  else
                    v_code := SQLCODE;
                    v_errm := SUBSTR(SQLERRM, 1, 64);
                    DBMS_OUTPUT.PUT_LINE('Error code ' || v_code || ': ' || v_errm);
                    raise;
                end if;  
            end; 
            -------------------------------------------------------------
            sesskilled := sesskilled + 1;
            msg := 'Session '||''''||to_char(c_sid)||','||to_char(c_serial)||''' for '||c_username||' was terminated';
            dbms_output.put_line(msg);  
          end if;
          
        END LOOP; 
      CLOSE c_sessions;
   
      -- After killing sessions
      display_mode(doit);
      execute immediate 'select count(1) from v$session ' into cnt;

      dbms_output.put_line('Remaining number of sessions is '||to_char(cnt));
      if doit then
        dbms_output.put_line(to_char(sesskilled)||' sessions were killed');
      end if;
    
     exception
        when others then
          v_code := SQLCODE;
          v_errm := SUBSTR(SQLERRM, 1, 64);
          DBMS_OUTPUT.PUT_LINE('Error code ' || v_code || ': ' || v_errm);
         raise;
  end enable_restricted;

  procedure disable_restricted ( revokeFrom all_users.username%type, doit boolean default false ) is
    /*
      Disable restricted mode on database
      revoke restricted session from OPCON OPCONAP
    */
    cmd        varchar2(80);
    cnt        integer;
    msg        varchar2(80);
    v_code     NUMBER;
    v_errm     VARCHAR2(64);
        
    begin
      -- Current number of sessions 
      execute immediate 'select count(1) from v$session ' into cnt;
      dbms_output.put_line(chr(10)||'Current number of sessions is '||to_char(cnt));
  
      cmd := 'ALTER SYSTEM DISABLE RESTRICTED SESSION';
      display_mode(doit);
      dbms_output.put_line(cmd);
      if doit then
        execute immediate cmd;
        msg := 'Restricted mode is now disabled';
        dbms_output.put_line(msg);
      end if;
 
      -- Check that user <<revokeFrom> exists in db
      dbms_output.put_line('Check that user '||revokeFrom||' exists in database');
      execute immediate 'select 1 from all_users where username = upper(:revokeFrom)' into cnt using revokeFrom;
      
      -- Revoke 'restricted session' from user <<revokeFrom>>
      cmd := 'REVOKE RESTRICTED SESSION from '||revokeFrom;
      display_mode(doit);
      dbms_output.put_line(cmd);
      if doit then
        execute immediate cmd;
      end if;
  
      exception
        when others then
          v_code := SQLCODE;
          v_errm := SUBSTR(SQLERRM, 1, 64);
          DBMS_OUTPUT.PUT_LINE('Error code ' || v_code || ': ' || v_errm);
          raise;
  end disable_restricted;
  
end solife_util;
/

