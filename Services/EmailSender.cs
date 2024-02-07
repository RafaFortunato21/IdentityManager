using Microsoft.Exchange.WebServices.Data;



namespace IdentityManager.Services
{
    public class EmailSender
    {


        public void SendEmail(string destinatario, string assunto, string msg )
        {

            ExchangeService service = new ExchangeService();
            service.Credentials = new WebCredentials("noreply", "!#S!5tem4@n0r3ply#!", "fserj.net");
            //service.AutodiscoverUrl("administrador@fs.rj.gov.br", RedirectionUrlValidationCallback);
            service.Url = new Uri("https://webmail.fs.rj.gov.br/EWS/Exchange.asmx");

            char[] delimitador = { '/' };

            string[] item = destinatario.Split(delimitador);


            EmailMessage message = new EmailMessage(service);
            message.Subject = assunto;
            message.Body = msg;

            foreach (var i in item)
            {
                message.ToRecipients.Add(i.Trim());
            }

            message.Send();

        }



    }

}
