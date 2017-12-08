unit QTorModule;

interface

Uses
    System.Classes, System.Variants, System.SysUtils,
    idHTTP, IdSSL, IdSSLOpenSSL, IdCookieManager,
    IdCustomTransparentProxy, IdSocks, IdTCPClient,
    Vcl.Controls, Vcl.Forms, Winapi.Windows, SyncObjs,
    RegularExpressions, tlhelp32, PsApi, ShellApi;

//Регулярные Выражения для поиска
Const
  RE_GL2 = '(?ism-x)(<h3)(.*?)((http|https)(.*?)(?=&amp;))';
  RE_GL5 = '(http|https)(.*)\w';
  RE_GL4 = '(?ism-x)(([0-9]{1,3}\.){3}([0-9]{1,3}))(.*?)((\d){2,5})';
  RE_GL_IP = '(?ism-x)(([0-9]{1,3}\.){3}([0-9]{1,3}))';
  RE_GL_PORT = '(?sim-x)[0-9]{2,5}$';

Const
  TOR_exe = 'TorBrowser\Tor\Tor.exe';

//Строка поиска по носкам
Const google_search = 'https://www.google.com/search?q=free+socks5+proxy&start=';
      check_url = 'https://google.com';
      inc_word = 'google';

//Тип для поиска по процессам
type TPROC = record
    h,h1:THandle;
    pe:TProcessEntry32;
    path: array[0..MAX_PATH - 1] of char;
end;

//Тип регулярных выражений
type TRegExp = record
  RegEx: TRegEx;
  Option: TRegExOptions;
  Pattern: String;
  RMath: TMatch;
  RMathes: TMatchCollection;
end;

//Парсер на основе Indy
type TParser = Class(TObject)
  var
    FHTTP: TIdHTTP;
    FSSL: TIdSSLIOHandlerSocketOpenSSL;
    FCookie: TIdCookieManager;
    RegExp: TRegExp;
  constructor Create;
  destructor Destroy; override;
  function AsHTML(Url: String): String;
end;

//Тип Прокси
type TSocks = record
  ID: Integer;
  IP, PORT, STYPE, LOGIN, PASSW: String;
  function InStrings: TStrings;
end;

//Объек сайт с прокси
type TLink = Class(TObject)
  public
    Url: String;
    Sockses: Array of TSocks;
    procedure SocksRandomize;
    procedure AddS(IP,PORT: String; STYPE: String=''; LOGIN: String=''; PASSW: String=''); overload;
    procedure AddS(Socks: TSocks); overload;
    procedure DelS; overload;
    constructor Create(Sender: TObject);
    Destructor Destroy; override;
End;

//Возвращает строку с уровнем директории выше
function UpDir(S: String; level: byte=1): String;
//Находит путь к папке с TOR путем поиска процессов tor.exe или firefox.exe и извлечением пути к процессу
function FindProcTorOrFF: String;
//Поиск процесса и завершение его по названию
function FindProc(ProcName: String): Boolean;
//Запуск потока поиска TOR папки
procedure FindTorDir_Start;
//Запускаем поток поиска сайтов с прокси
procedure ParserLinks_Start;
//Запуск потока поиска проксей на текущем сайте
procedure ParserLink_Start;
//Запуск потока поиска рабочего прокси из списка проски с текущего сайта
procedure FindWorkSocks_Start;
//Запус потока установки прокси в TOR
procedure InstallSocks_Start;
//Запус потока установки прокси в TOR
procedure RunCheck_Start;
//Смена панелей (0: Панель ожидания TOR Browser; 1: Панель контроля прокси)
procedure SetWindow(Index: Integer);
//Загружаем настройки из param.qtr
procedure LoadParam;
//Сохраняем настройки в param.qtr
procedure SaveParam;

Var
    LinksWithSocks: TStrings;//Список сайтов с прокси
    Link: TLink;//Сайт с проксями
    SParser: TParser;//Чекер прокси
    n_google: Integer = 0;//Номер страницы в поиске
    IndexLink: Integer = 0;//Номер текущего сайта с прокси в LinksWithSocks
    IndexSocks: Integer = 0;//Номер текущей прокси в Link
    FindTorDir, FindingTorDir, ParsedLinks, ParsingLinks, ParsedLink,
    ParsingLink, NeedSocks, FindedSocks, FindingSocks, InstalledSocks,
    InstallingSocks, RunChecking, InRunChecking, FindSocksEnable,
    InstallSocksEnable: Boolean;//Логические переменные состояний потоков
    TorDir, torrc: String;//Переменные путей папки TOR и файла torrc

implementation

uses QTorUnit;

//Запуск потока проверки работоспособности прокси
procedure RunCheck_Start;
begin
  InRunChecking :=True;
  TThread.CreateAnonymousThread(procedure
        Var SocksInfo: TIdSocksInfo;
        Resp,Old_IP: String;
        Live: Boolean;
        Count: Integer;
    begin
      Live :=False;
      Old_IP :=Link.Sockses[IndexSocks].IP;
      Sleep(30000);
      //Проверяем не сменился ли IP
      if Old_IP=Link.Sockses[IndexSocks].IP then
      begin
      With QTorWindow do
        begin
          SocksInfo_IP.Caption :=Link.Sockses[IndexSocks].IP;
          SocksInfo_PORT.Caption :=Link.Sockses[IndexSocks].PORT;
          SocksInfo_Status.Caption :='In Checking';
        end;
      Count :=0;
      With SParser do
        While (Count<2) and (not Live) do
        try
          inc(Count);
          if Count=2 then Sleep(2000);
          FHTTP.Disconnect;
          SocksInfo :=TIdSocksInfo.Create();
            With SocksInfo do
              try
                Enabled :=True;
                Host :=Link.Sockses[IndexSocks].IP;
                Port :=StrToInt(Link.Sockses[IndexSocks].PORT);
                Authentication :=saNoAuthentication;
              except
              end;
          If Link.Sockses[IndexSocks].STYPE='SOCKS5' then
            try
              SocksInfo.Version :=svSocks5;
              FSSL.TransparentProxy :=SocksInfo;
              FHTTP.IOHandler :=FSSL;
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then Live :=True;
             except
              Live :=False;
             end else
          If Link.Sockses[IndexSocks].STYPE='SOCKS4' then
            try
              SocksInfo.Version :=svSocks4;
              FSSL.TransparentProxy :=SocksInfo;
              FHTTP.IOHandler :=FSSL;
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then Live :=True;
            except
              Live :=False;
            end else
          If Link.Sockses[IndexSocks].STYPE='HTTPS' then
            try
              FHTTP.IOHandler :=nil;
              FHTTP.ProxyParams.ProxyServer :=Link.Sockses[IndexSocks].IP;
              FHTTP.ProxyParams.ProxyPort :=StrToInt(Link.Sockses[IndexSocks].PORT);
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then Live :=True;
            except
              Live :=False;
            end else
          try
            SocksInfo.Version :=svSocks5;
            FSSL.TransparentProxy :=SocksInfo;
            FHTTP.IOHandler :=FSSL;
            Resp :=FHTTP.Get(check_url);
            If Pos(inc_word,Resp)>0 then
              begin
                Link.Sockses[IndexSocks].STYPE :='SOCKS5';
                Live :=True;
              end;
          except
            try
              SocksInfo.Version :=svSocks4;
              FSSL.TransparentProxy :=SocksInfo;
              FHTTP.IOHandler :=FSSL;
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then
                begin
                  Link.Sockses[IndexSocks].STYPE :='SOCKS4';
                  Live :=True;
                end;
            except
              try
                FHTTP.IOHandler :=nil;
                FHTTP.ProxyParams.ProxyServer :=Link.Sockses[IndexSocks].IP;
                FHTTP.ProxyParams.ProxyPort :=StrToInt(Link.Sockses[IndexSocks].PORT);
                Resp :=FHTTP.Get(check_url);
                If Pos(inc_word,Resp)>0 then
                  begin
                    Link.Sockses[IndexSocks].STYPE :='HTTPS';
                    Live :=True;
                  end;
              except
                Live :=False;
              end;
            end;
          end;
          SocksInfo.Free;
          if FHTTP.Connected then FHTTP.Disconnect;
          FHTTP.ProxyParams.ProxyServer :='';
          FHTTP.ProxyParams.ProxyPort :=0;
        finally
        end;
      If Live then
        begin
          QTorWindow.SocksInfo_Status.Caption :='LIVE';
          FindedSocks :=True;
        end else
        begin
          QTorWindow.SocksInfo_Status.Caption :='DEAD';
          Link.DelS;
          //Переходим на уровень поиска прокси
          RunLevel :=4;
          FindedSocks :=False;
          FindingSocks :=False;
          //Меняем иконку в трее на "Прокси не работает"
          QTorWindow.TrayQTorIcon.IconIndex :=0;
          QTorWindow.Icon :=QTorWindow.TrayQTorIcon.Icon;
          //Выводим сообщение о недоступности прокси
          QTorWindow.ShowHind('QTOR [ Прокси мертв','IP:PORT '+Link.Sockses[IndexSocks].IP+
          ':'+Link.Sockses[IndexSocks].PORT+' ]','Прокси мертв - '+Link.Sockses[IndexSocks].IP+':'+Link.Sockses[IndexSocks].PORT);
        end;
      end;
      InRunChecking :=False;
    end).Start;
end;

//Запус потока установки прокси в TOR
procedure InstallSocks_Start;
begin
  InstallingSocks :=True;
  TThread.CreateAnonymousThread(procedure
    Var Storrc: TStrings;
        i: Integer;
    begin
      if torrc<>'' then
      try
        If FileExists(torrc) then
          try
            Storrc :=TStringList.Create;
            Storrc.LoadFromFile(torrc);
            i:=0;
            While i<Storrc.Count do
              begin
              if (Pos('Socks4Proxy',Storrc[i])>0) or (Pos('Socks5Proxy',Storrc[i])>0) or
                  (Pos('Socks5ProxyUsername',Storrc[i])>0) or (Pos('Socks5ProxyPassword',Storrc[i])>0)
                  or (Pos('HTTPSProxy',Storrc[i])>0) or (Pos('HTTPSProxyAuthenticator',Storrc[i])>0) then
                    Storrc.Delete(i) else inc(i);
              end;
            //Добавление настроек прокси в torrc
            if Link.Sockses[IndexSocks].IP<>'' then
              Storrc.AddStrings(Link.Sockses[IndexSocks].InStrings);
            Storrc.SaveToFile(torrc);
            Storrc.Free;
            if Link.Sockses[IndexSocks].IP<>'' then
              TThread.CreateAnonymousThread(procedure
                Var j: Integer;
                begin
                  j :=0;
                  //Если tor.exe открыт, то он закрывается, а его открытие подтверждается в TOR Browser
                  If Findproc('tor.exe') then
                    begin
                      While (FindWindow('MozillaDialogClass',nil)=0) and (j<40) do
                        begin
                          Sleep(100);
                          inc(j);
                        end;
                      SetForegroundWindow(FindWindow('MozillaDialogClass',nil));
                      keybd_event(VK_RETURN, MapvirtualKey(VK_RETURN, 0), 0, 0);
                      keybd_event(VK_RETURN, MapvirtualKey(VK_RETURN, 0),KEYEVENTF_KEYUP , 0);
                    end;
                end).Start;
          except
          end;
        Sleep(10000);
        //Выводим сообщение о успешной установке прокси
        QTorWindow.ShowHind('QTOR [ Прокси Установлен','IP:PORT '+Link.Sockses[IndexSocks].IP+
          ':'+Link.Sockses[IndexSocks].PORT+' ]','Прокси Установлен - '+Link.Sockses[IndexSocks].IP+':'+Link.Sockses[IndexSocks].PORT);
        InstalledSocks :=True;
        InstallingSocks :=False;
      except
      end;
    end).Start;
end;

//Запуск потока поиска рабочего прокси из списка проски с текущего сайта
procedure FindWorkSocks_Start;
begin
  FindingSocks :=True;
  TThread.CreateAnonymousThread(procedure
    Var SocksInfo: TIdSocksInfo;
        Resp: String;
        Live: Boolean;
    begin
      Live :=False;
      //Заносим данные о прокси в QTorWindow >> SocksInfo
      With QTorWindow do
        begin
          SocksInfo_IP.Caption :=Link.Sockses[IndexSocks].IP;
          SocksInfo_PORT.Caption :=Link.Sockses[IndexSocks].PORT;
          SocksInfo_Status.Caption :='In Checking';
        end;
      With SParser do
        try
          FHTTP.Disconnect;
          SocksInfo :=TIdSocksInfo.Create();
            With SocksInfo do
              try
                Enabled :=True;
                Host :=Link.Sockses[IndexSocks].IP;
                Port :=StrToInt(Link.Sockses[IndexSocks].PORT);
                Authentication :=saNoAuthentication;
              except
              end;
          If Link.Sockses[IndexSocks].STYPE='SOCKS5' then
            try
              SocksInfo.Version :=svSocks5;
              FSSL.TransparentProxy :=SocksInfo;
              FHTTP.IOHandler :=FSSL;
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then Live :=True;
             except
              Live :=False;
             end else
          If Link.Sockses[IndexSocks].STYPE='SOCKS4' then
            try
              SocksInfo.Version :=svSocks4;
              FSSL.TransparentProxy :=SocksInfo;
              FHTTP.IOHandler :=FSSL;
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then Live :=True;
            except
              Live :=False;
            end else
          If Link.Sockses[IndexSocks].STYPE='HTTPS' then
            try
              FHTTP.IOHandler :=nil;
              FHTTP.ProxyParams.ProxyServer :=Link.Sockses[IndexSocks].IP;
              FHTTP.ProxyParams.ProxyPort :=StrToInt(Link.Sockses[IndexSocks].PORT);
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then Live :=True;
            except
              Live :=False;
            end else
          try
            SocksInfo.Version :=svSocks5;
            FSSL.TransparentProxy :=SocksInfo;
            FHTTP.IOHandler :=FSSL;
            Resp :=FHTTP.Get(check_url);
            If Pos(inc_word,Resp)>0 then
              begin
                Link.Sockses[IndexSocks].STYPE :='SOCKS5';
                Live :=True;
              end;
          except
            try
              SocksInfo.Version :=svSocks4;
              FSSL.TransparentProxy :=SocksInfo;
              FHTTP.IOHandler :=FSSL;
              Resp :=FHTTP.Get(check_url);
              If Pos(inc_word,Resp)>0 then
                begin
                  Link.Sockses[IndexSocks].STYPE :='SOCKS4';
                  Live :=True;
                end;
            except
              try
                FHTTP.IOHandler :=nil;
                FHTTP.ProxyParams.ProxyServer :=Link.Sockses[IndexSocks].IP;
                FHTTP.ProxyParams.ProxyPort :=StrToInt(Link.Sockses[IndexSocks].PORT);
                Resp :=FHTTP.Get(check_url);
                If Pos(inc_word,Resp)>0 then
                  begin
                    Link.Sockses[IndexSocks].STYPE :='HTTPS';
                    Live :=True;
                  end;
              except
                Live :=False;
              end;
            end;
          end;
          SocksInfo.Free;
          if FHTTP.Connected then FHTTP.Disconnect;
          FHTTP.ProxyParams.ProxyServer :='';
          FHTTP.ProxyParams.ProxyPort :=0;
        finally
        end;
      If Live then
        begin
          //Если прокси рабочий, поиск останавливается
          QTorWindow.SocksInfo_Status.Caption :='LIVE';
          FindedSocks :=True;
        end else
        begin
          //Если прокси не рабочий, то прокси удаляеться
          QTorWindow.SocksInfo_Status.Caption :='DEAD';
          Link.DelS;
        end;
      FindingSocks :=False;
    end).Start;
end;

//Запуск потока поиска проксей на текущем сайте
procedure ParserLink_Start;
begin
  ParsingLink :=True;
  TThread.CreateAnonymousThread(procedure
    Var i: Word;
        R: TRegExp;
        Parser: TParser;
        dSocks: TSocks;
    begin
      Parser :=TParser.Create;
      SetLength(Link.Sockses,0);
      With R do
        try
          RMathes :=RegEx.Matches(Parser.AsHTML(LinksWithSocks[IndexLink]),RE_GL4);
          if RMathes.Count>0 then
            begin
              For i:=0 to RMathes.Count-1 do
                begin
                  dSocks.IP :=RegEx.Match(RMathes[i].Value,RE_GL_IP).Value;
                  dSocks.PORT :=RegEx.Match(RMathes[i].Value,RE_GL_PORT).Value;
                  Link.AddS(dSocks);
                end;
              ParsedLink :=True;
            end else LinksWithSocks.Delete(IndexLink);
        except
        end;
      //Перемешиваем все прокси для рандомизации
      Link.SocksRandomize;
      IndexSocks :=0;
      ParsingLink :=False;
      Parser.Free;
    end).Start;
end;

//Запускаем поток поиска сайтов с прокси
procedure ParserLinks_Start;
begin
  ParsingLinks :=True;
  TThread.CreateAnonymousThread(procedure
    Var i: Word;
        dS: String;
        R: TRegExp;
        Parser: TParser;
    begin
      Parser :=TParser.Create;
      With R do
        try
          RMathes :=RegEx.Matches(Parser.AsHTML(google_search+IntToStr(n_google)),RE_GL2);
          For i:=0 to RMathes.Count-1 do
            begin
              dS :=RMathes.Item[i].Value;
              LinksWithSocks.Add(RegEx.Match(dS,(RE_GL5)).Value);
            end;
        except
        end;
      inc(n_google);
      Parser.Free;
      ParsedLinks :=True;
      ParsingLinks :=False;
    end).Start;
end;

//Запуск потока поиска TOR папки
procedure FindTorDir_Start;
Var TorDirPath: String;
begin
  FindingTorDir :=True;
  TorDirPath :=FindProcTorOrFF;
  If TorDirPath='' then
    begin
      SetWindow(0);
      TThread.CreateAnonymousThread(procedure
        Var TorDirPath: String;
        begin
          While TorDirPath='' do
            begin
              Sleep(2000);
              TorDirPath :=FindProcTorOrFF;
            end;
          TorDir :=TorDirPath;
          torrc :=TorDir+'TorBrowser\Data\Tor\torrc';
          FindTorDir :=True;
          FindingTorDir :=False;
          SetWindow(1);
        end).Start;
    end else
    begin
      TorDir :=TorDirPath;
      torrc :=TorDir+'TorBrowser\Data\Tor\torrc';
      FindTorDir :=True;
      FindingTorDir :=False;
    end;
end;

//Загружаем настройки из param.qtr
procedure LoadParam;
Var S: TStrings;
begin
  S :=TStringList.Create;
  if FileExists('param.qtr') then
    begin
      S.LoadFromFile('param.qtr');
      try
        If FileExists(S[0]+TOR_exe) then
          begin
            TorDir :=S[0];
            torrc :=TorDir+'TorBrowser\Data\Tor\torrc';
            FindTorDir :=True;
          end else FindTorDir :=False;
        If S[1]='0' then QTorWindow.AutoSeachProxy.Checked :=False;
        If S[2]='0' then QTorWindow.AutoInstallProxy.Checked :=False;
      except
        FindTorDir :=False;
      end;
    end;
end;

//Сохраняем настройки в param.qtr
procedure SaveParam;
Var S: TStrings;
begin
  S :=TStringList.Create;
  S.Add(TorDir);
  With QTorWindow do
    begin
      if AutoSeachProxy.Checked then S.Add('1') else S.Add('0');
      If AutoInstallProxy.Checked then S.Add('1') else S.Add('0');
    end;
  S.SaveToFile('param.qtr');
end;

//Смена панелей (0: Панель ожидания TOR Browser; 1: Панель контроля прокси)
procedure SetWindow(Index: Integer);
begin
  With QTorWindow do case Index of
    0: begin
        PanelControlSocks.Visible :=False;
        QTorWindow.ClientHeight :=90;
        PanelFindTor.Visible :=True;
    end;
    1: begin
        PanelFindTor.Visible :=False;
        QTorWindow.ClientHeight :=185;
        PanelControlSocks.Visible :=True;
    end;
  end;
end;

//Возвращает строку с уровнем директории выше
function UpDir(S: String; level: byte=1): String;
Var i,j: byte;
begin
  i :=Length(S);
  For j:=1 to level do
  try
    While S[i]<>'\' do
    try
      Delete(S,i,1);
      dec(i);
    except
    end;
    Delete(S,i,1);
  except
  end;
  Result :=S+'\';
end;

//Находит путь к папке с TOR путем поиска процессов tor.exe или firefox.exe и извлечением пути к процессу
function FindProcTorOrFF: String;
const
  PROCESS_TERMINATE = $0001;
var proc:TPROC;
    dS: String;
begin
  With proc do
    try
      pe.dwSize:=SizeOf(pe);
      h:=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
      If Process32First(h,pe) then
        While Process32Next(h,pe) do
          begin
          if (ExtractFileName(pe.szExeFile)='firefox.exe') or (ExtractFileName(pe.szExeFile)='tor.exe') then
            begin
              h1 := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ or PROCESS_TERMINATE, false, pe.th32ProcessID);
              GetModuleFileNameEx(h1, 0, path, MAX_PATH);
              dS :=UpDir(path);
              if ExtractFileName(pe.szExeFile)='firefox.exe' then
                if FileExists(dS+TOR_exe) then
                  begin
                    Result :=dS;
                    Break;
                  end;
              If ExtractFileName(pe.szExeFile)='tor.exe' then
                begin
                  Result :=UpDir(dS,3);
                  Break;
                end;
              CloseHandle(h1);
            end;
          end;
  finally
    CloseHandle(h);
  end;
end;

//Поиск процесса и завершение его по названию
function FindProc(ProcName: String): Boolean;
const
  PROCESS_TERMINATE = $0001;
var proc:TPROC;
begin
  Result :=False;
  With proc do
    try
      pe.dwSize:=SizeOf(pe);
      h:=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
      If Process32First(h,pe) then
        While Process32Next(h,pe) do
          begin
          if ExtractFileName(pe.szExeFile)=ProcName then
            begin
              h1 := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ or PROCESS_TERMINATE, false, pe.th32ProcessID);
              GetModuleFileNameEx(h1, 0, path, MAX_PATH);
              TerminateProcess(h1,4);
              CloseHandle(h1);
              Result :=True;
              break;
            end;
          end;
  finally
    CloseHandle(h);
  end;
end;

{ TParser }
constructor TParser.Create;
begin
  inherited;
  FSSL :=TIdSSLIOHandlerSocketOpenSSL.Create(nil);
  FSSL.ConnectTimeout:=5000;
  FSSL.ReadTimeout:=5000;
  FHTTP :=TIdHTTP.Create(nil);
  FCookie := TIdCookieManager.Create(nil);
  FHTTP.CookieManager :=FCookie;
  FHTTP.IOHandler :=FSSL;
  FHTTP.HandleRedirects :=True;
  FHTTP.AllowCookies :=True;
  FHTTP.ReadTimeout:=5000;
  FHTTP.ConnectTimeout :=5000;
end;
destructor TParser.Destroy;
begin
  FCookie.Free;
  FHTTP.Free;
  FSSL.Free;
  inherited;
end;
//Получаем ответ по Url запросу в String
function TParser.AsHTML(Url: string): String;
begin
  try
  Result :=FHTTP.Get(Url);
  FHTTP.Disconnect;
  except
  end;
end;

{ TSocks }
//Представляем прокси в виде строки для записи в torrc
function TSocks.InStrings;
begin
  Result :=TStringList.Create;
  if STYPE = 'SOCKS4' then
    begin
      Result.Add('Socks4Proxy '+IP+':'+PORT);
    end else
  if STYPE = 'SOCKS5' then
    begin
      Result.Add('Socks5Proxy '+IP+':'+PORT);
      if Login<>'' then
        begin
          Result.Add('Socks5ProxyUsername '+Login);
          Result.Add('Socks5ProxyPassword '+Passw);
        end;
    end else
  if STYPE = 'HTTPS' then
    begin
      Result.Add('HTTPSProxy '+IP+':'+PORT);
      if Login<>'' then Result.Add('HTTPSProxyAuthenticator '+Login+':'+Passw);
    end;
end;

{ TLink }
constructor TLink.Create(Sender: TObject);
begin
  Url :='';
end;
destructor TLink.Destroy;
begin
  SetLength(Sockses,0);
end;
//Добавляем запись прокси в массив с прокси
procedure TLink.AddS(IP,PORT: String; STYPE: String=''; LOGIN: String=''; PASSW: String='');
begin
  SetLength(Sockses, Length(Sockses)+1);
  Sockses[Length(Sockses)-1].IP :=IP;
  Sockses[Length(Sockses)-1].PORT :=PORT;
  Sockses[Length(Sockses)-1].STYPE :=STYPE;
  Sockses[Length(Sockses)-1].LOGIN :=LOGIN;
  Sockses[Length(Sockses)-1].PASSW :=PASSW;
end;
procedure TLink.AddS(Socks: TSocks);
begin
  SetLength(Sockses, Length(Sockses)+1);
  Sockses[Length(Sockses)-1].IP :=Socks.IP;
  Sockses[Length(Sockses)-1].PORT :=Socks.PORT;
  Sockses[Length(Sockses)-1].STYPE :=Socks.STYPE;
  Sockses[Length(Sockses)-1].LOGIN :=Socks.LOGIN;
end;
//Удаляем прокси из ссылки
procedure TLink.DelS;
Var i: Integer;
begin
  if Length(Sockses)>1 then
    begin
      for i:=1 to Length(Sockses)-1 do
          Sockses[i-1] :=Sockses[i];
      SetLength(Sockses,Length(Sockses)-1);
    end else SetLength(Sockses,0);
end;
//Перемешивание прокси, рандомизация
procedure TLink.SocksRandomize;
Var i,j,x: Word;
    dSocks: TSocks;
begin
  j :=Length(Sockses);
  Randomize;
  If j>0 then
    try
      For i:=0 to j-1 do
        begin
          dSocks :=Sockses[i];
          x :=Random(j);
          Sockses[i] :=Sockses[x];
          Sockses[x] :=dSocks;
        end;
    except
    end;
end;

end.
