unit QTorUnit;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.ExtCtrls, Vcl.ComCtrls, Vcl.Graphics,
  Vcl.StdCtrls, Vcl.Imaging.pngimage, Vcl.Menus, ShellApi, QTorModule,
  System.ImageList, Vcl.ImgList, SyncObjs;

type
  TQTorWindow = class(TForm)
    TrayQTorIcon: TTrayIcon;
    PopupMenu1: TPopupMenu;
    Exit_QTor: TMenuItem;
    TrayImages: TImageList;
    Body: TTimer;
    PanelFindTor: TPanel;
    Tor_Image: TImage;
    Event: TLabel;
    PanelControlSocks: TPanel;
    PanelSocksInfo: TGridPanel;
    Label1: TLabel;
    SocksInfo: TLabel;
    Label3: TLabel;
    SocksInfo_IP: TLabel;
    Label5: TLabel;
    SocksInfo_PORT: TLabel;
    Label2: TLabel;
    SocksInfo_Status: TLabel;
    PanelEnableQTor: TPanel;
    AutoSeachProxy: TCheckBox;
    PanelChangeSocks: TPanel;
    AutoInstallProxy: TCheckBox;
    ButtonChangeSocks: TButton;
    ButtonInstallProxy: TButton;
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure Exit_QTorClick(Sender: TObject);
    procedure ShowHind(title, msg: String; mhint: String = '');
    procedure BodyTimer(Sender: TObject);
    procedure AutoSeachProxyClick(Sender: TObject);
    procedure AutoInstallProxyClick(Sender: TObject);
    procedure ButtonChangeSocksClick(Sender: TObject);
    procedure ButtonInstallProxyClick(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure TrayQTorIconClick(Sender: TObject);
  private
  public
    { Public declarations }
  end;

var
  QTorWindow: TQTorWindow;
  RunLevel: Integer = 0;
  TrayClose: Boolean = False;


implementation

{$R *.dfm}

//����� ��������� � ����
procedure TQTorWindow.ShowHind(title: string; msg: string; mhint: String = '');
begin
  TrayQTorIcon.BalloonTitle :=title;
  TrayQTorIcon.BalloonHint :=msg;
  if mhint<>'' then TrayQTorIcon.Hint :=mhint;
  TrayQTorIcon.ShowBalloonHint;
end;

//��������� ���� ���������, �������� 1 ���
procedure TQTorWindow.BodyTimer(Sender: TObject);
Var torrc_old: TStrings;
begin
  if not FindTorDir then
    begin
      if not FindingTorDir then FindTorDir_Start;
    end else
    begin
      Case RunLevel of
        //������� �������� backup torrc
        0: try
            torrc_old :=TStringList.Create;
            torrc_old.LoadFromFile(torrc);
            torrc_old.SaveToFile(torrc+'.old');
            torrc_old.Clear;
            torrc_old.Add('DataDirectory '+TorDir+'TorBrowser\Data\Tor');
            torrc_old.Add('GeoIPFile '+TorDir+'TorBrowser\Data\Tor\geoip');
            torrc_old.Add('GeoIPv6File '+TorDir+'TorBrowser\Data\Tor\geoip6');
            torrc_old.SaveToFile(torrc);
            inc(RunLevel);
        except
          ShowMessage('��� ������� � �������������� ����� '+torrc);
          Close;
        end;
        //������� �������� ������� � ��������
        1: begin
            TThread.CreateAnonymousThread(procedure
              Var Parser: TParser;
                  Result: String;
              begin
                Parser :=TParser.Create;
                try
                  Result :=Parser.AsHTML(check_url);
                  If Result='' then Close;
                except
                  ShowMessage('��� ������� � ��������!');
                  QTorWindow.Close;
                end;
                Parser.Free;
              end).Start;
            ParsedLinks :=False;
            inc(RunLevel);
        end;
        //������� ������ ������ � ������
        2: begin
            If not ParsedLinks then
              begin
                SocksInfo.Caption :='������ ����� � ������...';
                If not ParsingLinks then begin
                  LinksWithSocks.Add('http://www.gatherproxy.com/sockslist');
                  ParserLinks_Start;
                end;
              end else
              begin
                ParsedLink :=False;
                ParsingLink :=False;
                inc(RunLevel);
              end;
        end;
        //������� �������� ������ � �������� �����
        3: begin
            If not ParsedLink then
              begin
                SocksInfo.Caption :='�������� ������...';
                If not ParsingLink then
                  begin
                    If LinksWithSocks.Count>0 then ParserLink_Start else
                      begin
                        ParsedLinks :=False;
                        RunLevel :=2;
                      end;
                  end;
              end else
              begin
                FindedSocks :=False;
                FindingSocks :=False;
                inc(RunLevel);
                SocksInfo.Caption :='�������';
              end;
        end;
        //������� ������ ������� ������
        4: begin
            ButtonInstallProxy.Enabled :=False;
            if (not AutoSeachProxy.Checked) and (not FindSocksEnable) then ButtonChangeSocks.Enabled :=True;
            If FindSocksEnable or AutoSeachProxy.Checked then
            If not FindedSocks then
              begin
                if FindSocksEnable then ButtonChangeSocks.Enabled :=False;
                SocksInfo.Caption :='���� ������� ������...';
                If not FindingSocks then
                  begin
                    If Length(Link.Sockses)>0 then FindWorkSocks_Start else
                      begin
                        LinksWithSocks.Delete(IndexLink);
                        ParsedLink :=False;
                        RunLevel :=3;
                      end;
                  end;
              end else
              begin
                InstalledSocks :=False;
                InstallingSocks :=False;
                If FindSocksEnable then
                  begin
                    FindSocksEnable :=False;
                    If not AutoSeachProxy.Checked then ButtonChangeSocks.Enabled :=True;
                  end;
                inc(RunLevel);
              end;
        end;
        //������� ��������� ������ � TOR
        5: begin
            if (not AutoInstallProxy.Checked) and (not InstallSocksEnable) then ButtonInstallProxy.Enabled :=True;
            If InstallSocksEnable or AutoInstallProxy.Checked then
            If not InstalledSocks then
              begin
                if InstallSocksEnable then ButtonInstallProxy.Enabled :=False;
                SocksInfo.Caption :='������������� ������ � TOR...';
                If not InstallingSocks then
                  begin
                    InstallSocks_Start;
                  end;
              end else
              begin
                SocksInfo.Caption :='���������� � TOR';
                TrayQTorIcon.IconIndex :=1;
                Icon :=TrayQTorIcon.Icon;
                RunChecking :=False;
                InRunChecking :=False;
                if InstallSocksEnable then
                  begin
                    InstallSocksEnable :=False;
                    If not AutoInstallProxy.Checked then ButtonInstallProxy.Enabled :=True;
                  end;
                inc(RunLevel);
              end;
        end;
        //������� ������
        6: begin
            If not RunChecking then
              begin
                If not InRunChecking then
                  begin
                    RunCheck_Start;
                  end;
              end;
        end;
      End;
    end;
end;

//������ ������ ����� ������� ������
procedure TQTorWindow.ButtonChangeSocksClick(Sender: TObject);
begin
  if RunLevel>3 then
    begin
      FindSocksEnable :=True;
      FindedSocks :=False;
      FindingSocks :=False;
      if Length(Link.Sockses)>0 then Link.DelS;
      RunLevel :=4;
    end;
end;

//������ ��������� ������
procedure TQTorWindow.ButtonInstallProxyClick(Sender: TObject);
begin
  If RunLevel>4 then
    begin
      InstallSocksEnable :=True;
      InstalledSocks :=False;
      InstallingSocks :=False;
      RunLevel :=5;
    end;
end;

//��������/�������� ��������� ������ ����� � ����
procedure TQTorWindow.TrayQTorIconClick(Sender: TObject);
begin
  QTorWindow.Visible :=not QTorWindow.Visible;
end;

//����� �� ��������� (Popup Menu Tray)
procedure TQTorWindow.Exit_QTorClick(Sender: TObject);
begin
  TrayClose :=True;
  Close;
end;

//�������� ���������
procedure TQTorWindow.FormCreate(Sender: TObject);
begin
  LoadParam;
  QTorWindow.ClientWidth :=240;
  PanelFindTor.Align :=alClient;
  PanelControlSocks.Align :=alClient;
  SetWindow(1);
  LinksWithSocks :=TStringList.Create;
  Link :=TLink.Create(nil);
  SParser :=TParser.Create;
  TrayQTorIcon.IconIndex :=0;
  Icon :=TrayQTorIcon.Icon;
  Body.Enabled :=True;
end;

//���������� ���������
procedure TQTorWindow.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  SaveParam;
  Link.Free;
  SParser.Free;
  //��������������� torrc �� backup
  If FileExists(torrc+'.old') then
    begin
      DeleteFile(torrc);
      RenameFile(torrc+'.old', torrc);
    end;
end;

//������� �������� ���������
procedure TQTorWindow.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  If not TrayClose then CanClose :=False;
  Hide;
end;

//������������� ������ � TOR
procedure TQTorWindow.AutoInstallProxyClick(Sender: TObject);
begin
  If RunLevel>4 then
    begin
      ButtonInstallProxy.Enabled :=not AutoInstallProxy.Checked;
      InstallSocksEnable :=False;
    end;
end;

//��������� ������� ������
procedure TQTorWindow.AutoSeachProxyClick(Sender: TObject);
begin
  If RunLevel>3 then
    begin
      ButtonChangeSocks.Enabled :=not AutoSeachProxy.Checked;
      FindSocksEnable :=False;
    end;
end;

end.
