<?php
session_start();                  //Starten van een sessie om later gebruik te maken van de sessie-ID
error_reporting(-1);              //Weergeven van errors (moet op 0 gezet worden in productie zodat er geen gevoelige informatie m.b.t. je code zichtbaar wordt voor eindgebruikers)
ini_set("display_errors", "on");  //Weergave van errors (moet op 'off' gezet worden in productie)

//Azure app ID registratie configuratie:
$client_id = "azure-client-id";          //Application client-ID
$ad_tenant = "azure-ad-tenant-id";          //Azure AD Tenant ID (van prizma testproject)
$client_secret = "azure-client-secret";  //Client Secret
$redirect_uri = "https://examplesite.com";                 //Dit moet 100% matchen met wat in Azure staat
$error_email = "barry.butsers@example.com";               //Email waarnaar errors zullen verstuurd worden
function errorhandler($input, $email)
{
  $output = "PHP Session ID:    " . session_id() . PHP_EOL;
  $output .= "Client IP Address: " . getenv("REMOTE_ADDR") . PHP_EOL;
  $output .= "Client Browser:    " . $_SERVER["HTTP_USER_AGENT"] . PHP_EOL;
  $output .= PHP_EOL;
  ob_start();  //Start capturing van de output buffer
  var_dump($input);  //Niet voor debug printing, maar om data te verzamelen voor de email
  $output .= ob_get_contents();  //Output buffer content opslaan in $output
  ob_end_clean();  //Opschonen output buffer en uitschakelen van buffering.

  //While testing, you probably want to comment the next row out
  mb_send_mail($email, "Your Azure AD Oauth2 script faced an error!", $output, "X-Priority: 1\nContent-Transfer-Encoding: 8bit\nX-Mailer: PHP/" . phpversion());
  exit;
}
if (isset($_GET["code"])) echo "<pre>";  //Code voor beter ogende var_dumps voor debug doeleinden (paste echo "<pre>" na de if haakjes om beter te gaan debuggen)
if (!isset($_GET["code"]) and !isset($_GET["error"])) {       //Echt begin van de authenticatie

  //Eerste stap van het authenticatie proces; De redirect naar de microsoft login pagina (first load of this page)
  $url = "https://login.microsoftonline.com/" . $ad_tenant . "/oauth2/v2.0/authorize?";
  $url .= "state=" . session_id();                                  //Semi-random string als state identifier
  $url .= "&scope=profile+openid+email+offline_access+User.Read";  //Je kan ook "&scope=User.Read" gebruiken
  $url .= "&response_type=code";
  $url .= "&approval_prompt=auto";
  $url .= "&client_id=" . $client_id;
  $url .= "&redirect_uri=" . urlencode($redirect_uri);
  header("Location: " . $url);       //Browser komt terug voor ronde 2 na enkele redirects van aan de Azure kant
} elseif (isset($_GET["error"])) {  //De tweede keer dat de pagina laad, waar geen errors zouden mogen verschijnen
  echo "Error handler activated:\n\n";
  var_dump($_GET);  //Debug print
  errorhandler(array("Description" => "Error received at the beginning of second stage.", "\$_GET[]" => $_GET, "\$_SESSION[]" => $_SESSION), $error_email);
} elseif (strcmp(session_id(), $_GET["state"]) == 0) {  //Checken of de session_id matcht met de state voor security redenen
  //echo "Post-redirect:\n\n";  //Browser returns from its various redirects at Azure side and carrying some gifts inside $_GET
  var_dump($_GET);  //Debug print
  //De ontvangen tokens verifiëren tegenover Azure
  $content = "grant_type=authorization_code";
  $content .= "&client_id=" . $client_id;
  $content .= "&redirect_uri=" . urlencode($redirect_uri);
  $content .= "&code=" . $_GET["code"];
  $content .= "&client_secret=" . urlencode($client_secret);
  $options = array(
    "http" => array(  //Gebruik van "http" als een request verzonden wordt in https
      "method"  => "POST",
      "header"  => "Content-Type: application/x-www-form-urlencoded\r\n" .
        "Content-Length: " . strlen($content) . "\r\n",
      "content" => $content
    )
  );
  $context  = stream_context_create($options);
  $json = file_get_contents("https://login.microsoftonline.com/" . $ad_tenant . "/oauth2/v2.0/token", false, $context);
  if ($json === false) errorhandler(array("Description" => "Error received during Bearer token fetch.", "PHP_Error" => error_get_last(), "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
  $authdata = json_decode($json, true);
  if (isset($authdata["error"])) errorhandler(array("Description" => "Bearer token fetch contained an error.", "\$authdata[]" => $authdata, "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
  var_dump($authdata);  //Debug print
  //Opvragen van de basis user informatie die nodig is voor je applicatie
  $options = array(
    "http" => array(  //Gebruik van "http" als een request verzonden wordt in https
      "method" => "GET",
      "header" => "Accept: application/json\r\n" .
        "Authorization: Bearer " . $authdata["access_token"] . "\r\n"
    )
  );
  $context = stream_context_create($options);
  $json = file_get_contents("https://graph.microsoft.com/v1.0/me", false, $context);
  if ($json === false) errorhandler(array("Description" => "Error received during user data fetch.", "PHP_Error" => error_get_last(), "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
  $userdata = json_decode($json, true);  //Dit zou nu de informatie van de ingelogde user moeten bevatten
  if (isset($userdata["error"])) errorhandler(array("Description" => "User data fetch contained an error.", "\$userdata[]" => $userdata, "\$authdata[]" => $authdata, "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
  var_dump($userdata);  //Debug print

  $context = stream_context_create($options);
  $json = file_get_contents("https://graph.microsoft.com/v1.0/me/memberOf", false, $context);
  if ($json === false) errorhandler(array("Description" => "Error received during user group data fetch.", "PHP_Error" => error_get_last(), "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
  $groupdata = json_decode($json, true);  //This should now contain your logged on user memberOf (groups) information
  if (isset($groupdata["error"])) errorhandler(array("Description" => "Group data fetch contained an error.", "\$groupdata[]" => $groupdata, "\$authdata[]" => $authdata, "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);
  var_dump($groupdata); 
} else {
  //Als we hier belanden is er iets verkeerd gegaan... Dit kan een hackpoging zijn omdat de verzonden en ontvangen status niet matchen en er geen $_GET["error"] is ontvangen.
  //echo "Hey, don't hack us!\n\n";
  //echo "PHP Session ID used as state: " . session_id() . "\n";  //In de productieomgeving zul je deze meldingen niet willen laten zien aan potentiële hackers
  var_dump($_GET);  //Maar dit is een test dus de var_dumps kunnen wel bruikbaar zijn
  errorhandler(array("Description" => "Possible hacking attempt, due state mismatch.", "\$_GET[]" => $_GET, "\$_SESSION[]" => $_SESSION), $error_email);
}
//echo "\n<a href=\"" . $redirect_uri . "\">Click here to redo the authentication</a>";  //Om het testen te vermakkelijken

  //This replaces all previous data in your session, but during login process you likely want to do that 
  $_SESSION = $userdata;
  $_SESSION["oauth_bearer"] = $authdata["access_token"];
  $_SESSION["groups"] = $groupdata; 
?>
<!DOCTYPE html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <title>Captive Portal</title>
    <style>
        body {font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;}
        #content,.login,.login-card a,.login-card h1,.login-help{text-align:center}
        body,html{margin:0;padding:0;width:100%;height:100%;display:table}
        #content{font-family:'Source Sans Pro',sans-serif;background-color:#1C1275;background:linear-gradient(135deg, #f3f5f6, #d3d3d0, #a5a5a7);-webkit-background-size:cover;-moz-background-size:cover;-o-background-size:cover;background-size:cover;display:table-cell;vertical-align:middle}
        .login-card{padding:50px;width:350px;background-color:#F7F7F7;margin:100px auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}
        .login-card img{width:70%;height:70%}
        .login-card input[type=submit]{width:100%;display:block;margin-bottom:10px;position:relative}
        .login-card a{text-decoration:none;color:rgb(0, 0, 0);font-weight:400;display:inline-block;opacity:.6;transition:opacity ease .5s}
    </style>
</head>

<body>
<div id="content">
    <div class="login-card">
        <img src="image.png" alt="Company Logo"><br>
            <div id="error-message">
            </div>
            <br>
            <select id="language-select" onchange="setLanguage()">
              <option value="nl">Nederlands</option>
              <option value="fr">Français</option>
              <option value="en">English</option>
            </select>
            <h2 id="Titel"></h2>
            <script>
              var select = document.getElementById("language-select");
              var prizma = document.getElementById("Titel");

              select.onchange = function() {
                var selectedLanguage = select.value;
                if (selectedLanguage === "nl") {
                  prizma.innerHTML = "Welkom bij onze organisatie";
                } else if (selectedLanguage === "fr") {
                  prizma.innerHTML = "Bienveneu chez notre organisation";
                } else if (selectedLanguage === "en") {
                  prizma.innerHTML = "Welcome to our organisation";
                }
              }
            </script>
            <p></p>
                <label for="tos-checkbox"><i>Ik stem in met de&nbsp;</i><a href="tos.html" style="color: rgb(18, 123, 222);" target="_blank"><i>gebruiksvoorwaarden&nbsp;</i></a>
                <input type="checkbox" id="tos-checkbox" name="terms" required>
                </label>
                <p></p>
            <form method="POST" action="https://login.microsoftonline.com/azure-ad-tenant/oauth2/authorize" onsubmit="return checkTOS();">
                <input type="hidden" name="client_id" value="azure-client-id">
                <input type="hidden" name="response_type" value="code">
                <input type="hidden" name="redirect_uri" value="https://examplesite.com">
                <input type="hidden" name="resource" value="https://graph.microsoft.com">
                <input type="hidden" name="prompt" value="login">
                <input type="submit" value="Microsoft 365 Login">
                <script>
                  function checkTOS() {
                    if(!document.getElementById("tos-checkbox").checked) {
                      alert("Je moet de gebruikersvoorwaarden accepteren vooraleer verder te gaan.");
                      return false;
                    }
                    return true;
                  }
                </script>
            </form>
        
</body>
</html>
