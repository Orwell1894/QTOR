program QTor;

uses
  Vcl.Forms,
  Vcl.Themes,
  Vcl.Styles,
  Winapi.Windows,
  QTorModule in 'QTorModule.pas',
  QTorUnit in 'QTorUnit.pas' {QTorWindow};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := False;
  Application.ShowMainForm :=False;
  TStyleManager.TrySetStyle('Windows10 Dark');
  Application.CreateForm(TQTorWindow, QTorWindow);
  ShowWindow(Application.Handle, SW_HIDE);
  Application.Run;
end.
