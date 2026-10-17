//! What the bot says to users (not the admin) in their language, set with
//! `/allow <username> <language>`. Command names stay English in every language;
//! `{name}` placeholders are filled in by the caller.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    #[default]
    En,
    Fr,
    De,
    Ru,
    Uk,
    Pl,
}

impl Language {
    pub const ALL: [Language; 6] = [Language::En, Language::Fr, Language::De, Language::Pl, Language::Ru, Language::Uk];

    /// The code the admin types (any case): EN, FR, GE, PL, RU, UA.
    pub fn code(self) -> &'static str {
        match self {
            Language::En => "EN",
            Language::Fr => "FR",
            Language::De => "GE",
            Language::Ru => "RU",
            Language::Uk => "UA",
            Language::Pl => "PL",
        }
    }

    /// Two letters, any case.
    pub fn parse(code: &str) -> Option<Language> {
        if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_alphabetic()) {
            return None;
        }
        Self::ALL.into_iter().find(|l| l.code().eq_ignore_ascii_case(code))
    }

    /// For the configuration: the chat codes, and also ISO 639-1's DE and UK.
    pub fn parse_setting(code: &str) -> Option<Language> {
        match code.to_ascii_uppercase().as_str() {
            "DE" => Some(Language::De),
            "UK" => Some(Language::Uk),
            _ => Self::parse(code),
        }
    }

    pub fn texts(self) -> &'static Texts {
        match self {
            Language::En => &EN,
            Language::Fr => &FR,
            Language::De => &DE,
            Language::Ru => &RU,
            Language::Uk => &UK,
            Language::Pl => &PL,
        }
    }
}

/// A list of language codes ([`Language::parse_setting`]), separated by commas or blanks,
/// without repeats.
pub fn parse_languages(list: &str) -> Result<Vec<Language>, String> {
    let mut out = Vec::new();
    for code in list.split([',', ' ', ';']).map(str::trim).filter(|c| !c.is_empty()) {
        let lang = Language::parse_setting(code).ok_or_else(|| format!("unknown language '{code}' (EN, FR, GE, PL, RU, UA)"))?;
        if !out.contains(&lang) {
            out.push(lang);
        }
    }
    if out.is_empty() {
        return Err("no language".into());
    }
    Ok(out)
}

pub struct Texts {
    /// {admin}
    pub help: &'static str,
    pub not_a_command: &'static str,
    pub parse_error: &'static str,
    pub no_command: &'static str,
    /// {cmd}
    pub unknown_command: &'static str,
    pub usage: &'static str,
    pub example: &'static str,
    /// Arguments and an example of /abuse.
    pub abuse_args: &'static str,
    pub abuse_example: &'static str,
    pub invalid_username: &'static str,
    /// {url}
    pub invite: &'static str,
    /// Followed by the link.
    pub reset_link: &'static str,
    pub reset_link_xmpp: &'static str,
    pub reset_link_failed: &'static str,
    /// {user}
    pub cannot_report: &'static str,
    pub report_once: &'static str,
    pub report_accepted: &'static str,
    pub report_failed: &'static str,
    /// {time}
    pub not_run_late: &'static str,
    pub minutes: &'static str,
    pub hours: &'static str,
    pub omemo_required: &'static str,
    pub omemo_off_send_plain: &'static str,
    pub omemo_off: &'static str,
    /// {error}
    pub decrypt_failed: &'static str,
    /// {fp}; the `<jid> <fingerprint>` line to send to the admin follows.
    pub untrusted_key: &'static str,
    /// Instead of an error text that names server paths.
    pub internal_error: &'static str,
    pub encrypt_failed: &'static str,
    /// {id}, {fp}
    pub bot_device: &'static str,
    /// {n}
    pub your_devices: &'static str,
    pub key_pinned: &'static str,
    pub key_blind: &'static str,
    pub key_untrusted: &'static str,
    pub no_session: &'static str,
    /// {n}
    pub devices_title: &'static str,
    pub devices_none: &'static str,
    pub this_device: &'static str,
    /// {time}
    pub online_for: &'static str,
    pub devices_footer: &'static str,
    pub logout_args: &'static str,
    /// {device}
    pub logout_done: &'static str,
    /// {device}, {arg}
    pub logout_current: &'static str,
    pub no_such_device: &'static str,
    /// {mam}, {offline}
    pub storage: &'static str,
    pub delete_history_ask: &'static str,
    pub history_deleted: &'static str,
    /// In the new language.
    pub lang_set: &'static str,
    pub unknown_language: &'static str,
    pub motd_none: &'static str,
    /// A user's command failed; ejabberd's error is only logged.
    pub failed: &'static str,
    pub days: &'static str,
    /// {domain}, {messages}, {files}, {quota} (MB per file), {accounts}, {rooms}, {reports}, {security}
    pub privacy: &'static str,
    /// {domain}, {jid}, {date}
    pub export_title: &'static str,
    pub export_account: &'static str,
    /// {time}
    pub export_last: &'static str,
    pub export_online: &'static str,
    pub export_profile: &'static str,
    /// Full name, nickname, birthday, website, about, email, phone.
    pub vcard_labels: [&'static str; 7],
    /// {n}
    pub export_contacts: &'static str,
    /// {n}
    pub export_rooms: &'static str,
    /// {n}
    pub export_devices: &'static str,
    pub export_messages: &'static str,
    /// {n}
    pub export_invites: &'static str,
    pub invite_open: &'static str,
    pub invite_used: &'static str,
    pub invite_expired: &'static str,
    pub export_bot: &'static str,
    /// {lang}
    pub export_language: &'static str,
    /// {n}
    pub export_reports_by: &'static str,
    /// {n}
    pub export_reports_about: &'static str,
    pub export_none: &'static str,
    /// {messages}, {files}
    pub export_footer: &'static str,
    /// The message with /export's file: {file}, {kb}, {days}
    pub export_file: &'static str,
    pub export_file_needs_omemo: &'static str,
    pub export_file_failed: &'static str,

    // Server announcements (/maintenance, /restart, /warn): one paragraph per language of
    // ANNOUNCE_LANGUAGES, times in the language's time zone.
    pub flag: &'static str,
    pub tz: chrono_tz::Tz,
    pub today: &'static str,
    pub tomorrow: &'static str,
    /// Monday first.
    pub weekdays: [&'static str; 7],
    pub range_from: &'static str,
    pub range_to: &'static str,
    /// Between hours and minutes: "14:00", "14h00".
    pub time_separator: &'static str,
    pub maintenance_subject: &'static str,
    /// {range}: "from Today 02:00 to Today 03:00 (BST)"
    pub maintenance_notice: &'static str,
    /// {minutes}
    pub restart_notice: &'static str,
    pub warning_subject: &'static str,
}

pub const EN: Texts = Texts {
    help: "\
`/invite` — invite someone to this server
`/resetlink` — link to set a new password for your account
`/devices` — your connected devices
`/logout <number|device>` — disconnect one of your devices
`/storage` — your messages kept on the server
`/delete_history confirm` — delete your message archive on the server
`/motd` — current message of the day
`/lang <EN|FR|GE|PL|RU|UA>` — language of the bot's replies
`/abuse <username> [reason]` — report user
`/export` — a copy of your data on the server
`/privacy` — how long the server keeps your data
`/omemo` — show OMEMO fingerprints
`/help` — show this help

Questions or problems? Write to the admin: {admin}",
    not_a_command: "Commands must start with '/'. Type '/help'.",
    parse_error: "Command parsing error: No closing quotation",
    no_command: "No command specified. Type '/help'.",
    unknown_command: "Unknown command: '{cmd}'. Type '/help'.",
    usage: "Usage",
    example: "Example",
    abuse_args: "<username> [reason]",
    abuse_example: "john 'Spam account'",
    invalid_username: "✗ Invalid username.",
    invite: "To invite someone, open\n{url}\nsign in with your account and create an invitation. Send them the link it gives you: \
             it lets them register an account on this server.",
    reset_link: "✓ Link to set a new password for your account (single use; valid for the invitation lifetime, 5 days by default):",
    reset_link_xmpp: "For XMPP clients that support it:",
    reset_link_failed: "✗ Could not create a reset link. Please ask the admin.",
    cannot_report: "✗ '{user}' can not be reported.",
    report_once: "✗ You can report the same user only once.",
    report_accepted: "✓ Your abuse report is accepted.",
    report_failed: "✗ Could not save your report. Please tell the admin.",
    not_run_late: "✗ Not run: this command was sent {time} ago and reached the bot only now. Send it again to run it.",
    minutes: "min",
    hours: "h",
    omemo_required: "✗ This bot only accepts OMEMO-encrypted messages. Turn on OMEMO for this chat.",
    omemo_off_send_plain: "✗ OMEMO is turned off on this bot; send the command unencrypted.",
    omemo_off: "OMEMO is turned off on this bot.",
    decrypt_failed: "✗ Could not decrypt your OMEMO message ({error}). Send it again; if that fails, refresh this contact's OMEMO keys.",
    untrusted_key: "✗ This device's OMEMO key is not trusted by the bot:\n`{fp}`\nTo have it trusted, send this line to the admin:",
    internal_error: "internal error",
    encrypt_failed: "✗ Could not encrypt the reply (details in the bot's log).",
    bot_device: "Bot OMEMO device {id}\nFingerprint: `{fp}`\n",
    your_devices: "\nYour devices ({n}):",
    key_pinned: "pinned",
    key_blind: "trusted (not pinned)",
    key_untrusted: "*NOT trusted*",
    no_session: "no session yet",
    devices_title: "Your connected devices ({n}):",
    devices_none: "No devices are connected.",
    this_device: "this device",
    online_for: "online for {time}",
    devices_footer: "Check this list now and then. If you don't recognise a device, disconnect it with `/logout <number>` and set a new password with `/resetlink`: otherwise it connects again with the saved password.",
    logout_args: "<number|device>",
    logout_done: "✓ Disconnected: {device}. If it has your password saved, it connects again; to lock it out, set a new password with /resetlink.",
    logout_current: "{device} is the device you are writing from. To disconnect it anyway:\n`/logout {arg} confirm`",
    no_such_device: "✗ No such device. Send /devices for the list.",
    storage: "Messages in your server archive: {mam}\nMessages waiting for delivery: {offline}",
    delete_history_ask: "This deletes all your messages from the server archive. Copies on your devices stay. To proceed:\n`/delete_history confirm`",
    history_deleted: "✓ Your message archive on the server is deleted.",
    lang_set: "✓ Language: English.",
    unknown_language: "✗ Unknown language. Use one of: EN, FR, GE, PL, RU, UA.",
    motd_none: "No message of the day.",
    failed: "✗ That didn't work. Please ask the admin.",
    days: "d",
    privacy: "*Privacy and data retention on {domain}*\n\n*Messages*\n• Archived messages (also in group chats) are deleted after {messages} days.\n• Messages waiting for a contact who is offline are deleted after {messages} days.\n• OMEMO-encrypted messages are stored encrypted: the server can't read them.\n  https://en.wikipedia.org/wiki/OMEMO\n\n*Files*\n• Uploaded files (pictures, voice messages, …; up to {quota} MB each) are deleted after {files} days.\n\n*Accounts*\n• An account not used for {accounts} days is deleted with all its data: contacts, profile, messages.\n• Group chats not used for {rooms} days are deleted.\n• Registrations for push notifications are deleted after {messages} days.\n• Passwords are stored only as salted hashes (SCRAM), never in plain text.\n  https://en.wikipedia.org/wiki/Salted_Challenge_Response_Authentication_Mechanism\n• Invitation and password reset links expire after 5 days and are then deleted.\n\n*Logs and security*\n• Server logs (logins, IP addresses) are deleted after 14 days at the latest.\n• Security records (blocked addresses, suspicious logins and the reasons) are kept up to {security} days.\n• Both are used only for security: to protect your account, for example against someone guessing your password, and the whole server against attacks.\n• Once a week the administrator gets an encrypted report of the blocked addresses and what they did, without account names, to report the attacks to the networks they come from. The server holds it only encrypted, for at most {files} days.\n\n*This bot*\n• Chats with the bot are not archived.\n• The bot keeps only who may use it, each user's language and abuse reports, which it deletes after {reports} days, as well as everything about deleted accounts.\n• Its log records which commands were used, never their content, and is deleted after 14 days at the latest.",
    export_title: "*Your data on {domain}*\n{jid}, as of {date}",
    export_account: "*Account*",
    export_last: "Last login or logout: {time}",
    export_online: "online now",
    export_profile: "*Profile (vCard)*",
    vcard_labels: ["Full name", "Nickname", "Birthday", "Website", "About", "Email", "Phone"],
    export_contacts: "*Contacts ({n})*",
    export_rooms: "*Group chats ({n})*",
    export_devices: "*Connected devices ({n})*",
    export_messages: "*Stored messages*",
    export_invites: "*Invitations you created ({n})*",
    invite_open: "open",
    invite_used: "used",
    invite_expired: "expired",
    export_bot: "*This bot*",
    export_language: "Language: {lang}",
    export_reports_by: "Your abuse reports ({n}):",
    export_reports_about: "Reports about you: {n}",
    export_none: "none",
    export_footer: "Not included: the messages themselves (your client downloads them from the server archive, which keeps them {messages} days), files you sent (linked in your chats, kept {files} days) and server logs.",
    export_file: "📎 {file} ({kb} KB): the full copy of your data, archived messages included, as JSON. Encrypted: the server deletes its (encrypted) copy after {days} days.",
    export_file_needs_omemo: "The full copy as a file is sent only in an OMEMO-encrypted chat. Turn on OMEMO for this chat and send /export again.",
    export_file_failed: "✗ The file with the full copy could not be sent. Please try again later.",

    flag: "🇬🇧",
    tz: chrono_tz::Europe::London,
    today: "Today",
    tomorrow: "Tomorrow",
    weekdays: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
    range_from: "from",
    range_to: "to",
    time_separator: ":",
    maintenance_subject: "Server maintenance",
    maintenance_notice: "The server will be down for maintenance {range}.",
    restart_notice: "The server will restart in {minutes} min, for about a minute.",
    warning_subject: "Important update",
};

pub const FR: Texts = Texts {
    help: "\
`/invite` — inviter quelqu'un sur ce serveur
`/resetlink` — lien pour définir un nouveau mot de passe pour votre compte
`/devices` — vos appareils connectés
`/logout <numéro|appareil>` — déconnecter l'un de vos appareils
`/storage` — vos messages conservés sur le serveur
`/delete_history confirm` — supprimer votre archive de messages sur le serveur
`/motd` — message du jour
`/lang <EN|FR|GE|PL|RU|UA>` — langue des réponses du bot
`/abuse <utilisateur> [raison]` — signaler un utilisateur
`/export` — une copie de vos données sur le serveur
`/privacy` — combien de temps le serveur conserve vos données
`/omemo` — afficher les empreintes OMEMO
`/help` — afficher cette aide

Une question ou un problème ? Écrivez à l'administrateur : {admin}",
    not_a_command: "Les commandes doivent commencer par '/'. Tapez '/help'.",
    parse_error: "Erreur d'analyse de la commande : guillemet fermant manquant",
    no_command: "Aucune commande indiquée. Tapez '/help'.",
    unknown_command: "Commande inconnue : '{cmd}'. Tapez '/help'.",
    usage: "Utilisation",
    example: "Exemple",
    abuse_args: "<utilisateur> [raison]",
    abuse_example: "john 'Compte de spam'",
    invalid_username: "✗ Nom d'utilisateur invalide.",
    invite:
        "Pour inviter quelqu'un, ouvrez\n{url}\nconnectez-vous avec votre compte et créez une invitation. Envoyez-lui le lien obtenu : \
             il lui permet de créer un compte sur ce serveur.",
    reset_link: "✓ Lien pour définir un nouveau mot de passe pour votre compte (usage unique ; valable aussi longtemps qu'une invitation, \
                 5 jours par défaut) :",
    reset_link_xmpp: "Pour les clients XMPP qui le prennent en charge :",
    reset_link_failed: "✗ Impossible de créer un lien de réinitialisation. Veuillez contacter l'administrateur.",
    cannot_report: "✗ '{user}' ne peut pas être signalé.",
    report_once: "✗ Vous ne pouvez signaler un même utilisateur qu'une seule fois.",
    report_accepted: "✓ Votre signalement a été enregistré.",
    report_failed: "✗ Impossible d'enregistrer votre signalement. Veuillez prévenir l'administrateur.",
    not_run_late: "✗ Non exécutée : cette commande a été envoyée il y a {time} et n'est arrivée au bot que maintenant. \
                   Renvoyez-la pour l'exécuter.",
    minutes: "min",
    hours: "h",
    omemo_required: "✗ Ce bot n'accepte que les messages chiffrés avec OMEMO. Activez OMEMO pour cette conversation.",
    omemo_off_send_plain: "✗ OMEMO est désactivé sur ce bot ; envoyez la commande sans chiffrement.",
    omemo_off: "OMEMO est désactivé sur ce bot.",
    decrypt_failed: "✗ Impossible de déchiffrer votre message OMEMO ({error}). Renvoyez-le ; si cela échoue, \
                     actualisez les clés OMEMO de ce contact.",
    untrusted_key: "✗ La clé OMEMO de cet appareil n'est pas approuvée par le bot :\n`{fp}`\n\
                    Pour la faire approuver, envoyez cette ligne à l'administrateur :",
    internal_error: "erreur interne",
    encrypt_failed: "✗ Impossible de chiffrer la réponse (détails dans le journal du bot).",
    bot_device: "Appareil OMEMO du bot {id}\nEmpreinte : `{fp}`\n",
    your_devices: "\nVos appareils ({n}) :",
    key_pinned: "épinglée",
    key_blind: "approuvée (non épinglée)",
    key_untrusted: "*NON approuvée*",
    no_session: "pas encore de session",
    devices_title: "Vos appareils connectés ({n}) :",
    devices_none: "Aucun appareil connecté.",
    this_device: "cet appareil",
    online_for: "connecté depuis {time}",
    devices_footer: "Vérifiez cette liste de temps en temps. Si vous ne reconnaissez pas un appareil, déconnectez-le avec `/logout <numéro>` et définissez un nouveau mot de passe avec `/resetlink` : sinon il se reconnecte avec le mot de passe enregistré.",
    logout_args: "<numéro|appareil>",
    logout_done: "✓ Déconnecté : {device}. S'il a enregistré votre mot de passe, il se reconnectera ; pour l'en empêcher, définissez un nouveau mot de passe avec /resetlink.",
    logout_current: "{device} est l'appareil depuis lequel vous écrivez. Pour le déconnecter quand même :\n`/logout {arg} confirm`",
    no_such_device: "✗ Appareil introuvable. Envoyez /devices pour voir la liste.",
    storage: "Messages dans votre archive sur le serveur : {mam}\nMessages en attente de remise : {offline}",
    delete_history_ask: "Cela supprime tous vos messages de l'archive du serveur. Les copies sur vos appareils restent. Pour continuer :\n`/delete_history confirm`",
    history_deleted: "✓ Votre archive de messages sur le serveur a été supprimée.",
    lang_set: "✓ Langue : français.",
    unknown_language: "✗ Langue inconnue. Choisissez parmi : EN, FR, GE, PL, RU, UA.",
    motd_none: "Pas de message du jour.",
    failed: "✗ Cela n'a pas fonctionné. Veuillez contacter l'administrateur.",
    days: "j",
    privacy: "*Confidentialité et conservation des données sur {domain}*\n\n*Messages*\n• Les messages archivés (y compris dans les salons) sont supprimés au bout de {messages} jours.\n• Les messages en attente pour un contact hors ligne sont supprimés au bout de {messages} jours.\n• Les messages chiffrés avec OMEMO sont stockés chiffrés : le serveur ne peut pas les lire.\n  https://fr.wikipedia.org/wiki/OMEMO\n\n*Fichiers*\n• Les fichiers envoyés (images, messages vocaux, … ; {quota} Mo maximum chacun) sont supprimés au bout de {files} jours.\n\n*Comptes*\n• Un compte inutilisé pendant {accounts} jours est supprimé avec toutes ses données : contacts, profil, messages.\n• Les salons inutilisés pendant {rooms} jours sont supprimés.\n• Les inscriptions aux notifications push sont supprimées au bout de {messages} jours.\n• Les mots de passe sont stockés uniquement sous forme de hachages salés (SCRAM), jamais en clair.\n  https://en.wikipedia.org/wiki/Salted_Challenge_Response_Authentication_Mechanism\n• Les liens d'invitation et de réinitialisation expirent au bout de 5 jours, puis sont supprimés.\n\n*Journaux et sécurité*\n• Les journaux du serveur (connexions, adresses IP) sont supprimés au plus tard au bout de 14 jours.\n• Les relevés de sécurité (adresses bloquées, connexions suspectes et leurs raisons) sont conservés jusqu'à {security} jours.\n• Les deux servent uniquement à la sécurité : protéger votre compte, par exemple contre quelqu'un qui tente de deviner votre mot de passe, et le serveur tout entier contre les attaques.\n• Une fois par semaine, l'administrateur reçoit un rapport chiffré des adresses bloquées et de ce qu'elles ont fait, sans noms de compte, pour signaler les attaques aux réseaux d'où elles viennent. Le serveur ne le conserve que chiffré, {files} jours au plus.\n\n*Ce bot*\n• Les conversations avec le bot ne sont pas archivées.\n• Le bot conserve seulement qui peut l'utiliser, la langue de chacun et les signalements d'abus, qu'il supprime au bout de {reports} jours, de même que tout ce qui concerne les comptes supprimés.\n• Son journal indique quelles commandes ont été utilisées, jamais leur contenu, et il est supprimé au plus tard au bout de 14 jours.",
    export_title: "*Vos données sur {domain}*\n{jid}, au {date}",
    export_account: "*Compte*",
    export_last: "Dernière connexion ou déconnexion : {time}",
    export_online: "en ligne",
    export_profile: "*Profil (vCard)*",
    vcard_labels: ["Nom complet", "Pseudo", "Date de naissance", "Site web", "À propos", "E-mail", "Téléphone"],
    export_contacts: "*Contacts ({n})*",
    export_rooms: "*Salons ({n})*",
    export_devices: "*Appareils connectés ({n})*",
    export_messages: "*Messages conservés*",
    export_invites: "*Invitations que vous avez créées ({n})*",
    invite_open: "ouverte",
    invite_used: "utilisée",
    invite_expired: "expirée",
    export_bot: "*Ce bot*",
    export_language: "Langue : {lang}",
    export_reports_by: "Vos signalements d'abus ({n}) :",
    export_reports_about: "Signalements vous concernant : {n}",
    export_none: "aucun",
    export_footer: "Non inclus : les messages eux-mêmes (votre client les télécharge depuis l'archive du serveur, qui les conserve {messages} jours), les fichiers que vous avez envoyés (liés dans vos conversations, conservés {files} jours) et les journaux du serveur.",
    export_file: "📎 {file} ({kb} Ko) : la copie complète de vos données, messages archivés compris, en JSON. Chiffrée : le serveur supprime sa copie (chiffrée) après {days} jours.",
    export_file_needs_omemo: "La copie complète en fichier n'est envoyée que dans une conversation chiffrée avec OMEMO. Activez OMEMO pour cette conversation et renvoyez /export.",
    export_file_failed: "✗ Le fichier avec la copie complète n'a pas pu être envoyé. Veuillez réessayer plus tard.",

    flag: "🇫🇷",
    tz: chrono_tz::Europe::Paris,
    today: "Aujourd'hui",
    tomorrow: "Demain",
    weekdays: ["Lun", "Mar", "Mer", "Jeu", "Ven", "Sam", "Dim"],
    range_from: "de",
    range_to: "à",
    time_separator: "h",
    maintenance_subject: "Maintenance du serveur",
    maintenance_notice: "Le serveur sera indisponible pour maintenance {range}.",
    restart_notice: "Le serveur redémarrera dans {minutes} min, pour environ une minute.",
    warning_subject: "Mise à jour importante",
};

pub const DE: Texts = Texts {
    help: "\
`/invite` — jemanden auf diesen Server einladen
`/resetlink` — Link zum Festlegen eines neuen Passworts für Ihr Konto
`/devices` — Ihre verbundenen Geräte
`/logout <nummer|gerät>` — eines Ihrer Geräte abmelden
`/storage` — Ihre auf dem Server gespeicherten Nachrichten
`/delete_history confirm` — Ihr Nachrichtenarchiv auf dem Server löschen
`/motd` — Nachricht des Tages
`/lang <EN|FR|GE|PL|RU|UA>` — Sprache der Antworten des Bots
`/abuse <benutzername> [grund]` — Benutzer melden
`/export` — eine Kopie Ihrer Daten auf dem Server
`/privacy` — wie lange der Server Ihre Daten speichert
`/omemo` — OMEMO-Fingerabdrücke anzeigen
`/help` — diese Hilfe anzeigen

Fragen oder Probleme? Schreiben Sie dem Administrator: {admin}",
    not_a_command: "Befehle müssen mit '/' beginnen. Geben Sie '/help' ein.",
    parse_error: "Fehler beim Lesen des Befehls: schließendes Anführungszeichen fehlt",
    no_command: "Kein Befehl angegeben. Geben Sie '/help' ein.",
    unknown_command: "Unbekannter Befehl: '{cmd}'. Geben Sie '/help' ein.",
    usage: "Verwendung",
    example: "Beispiel",
    abuse_args: "<benutzername> [grund]",
    abuse_example: "john 'Spam-Konto'",
    invalid_username: "✗ Ungültiger Benutzername.",
    invite: "Um jemanden einzuladen, öffnen Sie\n{url}\nmelden Sie sich mit Ihrem Konto an und erstellen Sie eine Einladung. \
             Senden Sie der Person den erhaltenen Link: Damit kann sie ein Konto auf diesem Server anlegen.",
    reset_link: "✓ Link zum Festlegen eines neuen Passworts für Ihr Konto (einmalig nutzbar; so lange gültig wie eine Einladung, \
                 standardmäßig 5 Tage):",
    reset_link_xmpp: "Für XMPP-Clients, die das unterstützen:",
    reset_link_failed: "✗ Der Link zum Zurücksetzen konnte nicht erstellt werden. Bitte wenden Sie sich an den Administrator.",
    cannot_report: "✗ '{user}' kann nicht gemeldet werden.",
    report_once: "✗ Sie können denselben Benutzer nur einmal melden.",
    report_accepted: "✓ Ihre Meldung wurde angenommen.",
    report_failed: "✗ Ihre Meldung konnte nicht gespeichert werden. Bitte informieren Sie den Administrator.",
    not_run_late: "✗ Nicht ausgeführt: Dieser Befehl wurde vor {time} gesendet und hat den Bot erst jetzt erreicht. \
                   Senden Sie ihn erneut, um ihn auszuführen.",
    minutes: "Min.",
    hours: "Std.",
    omemo_required: "✗ Dieser Bot nimmt nur OMEMO-verschlüsselte Nachrichten an. Aktivieren Sie OMEMO für diesen Chat.",
    omemo_off_send_plain: "✗ OMEMO ist bei diesem Bot ausgeschaltet; senden Sie den Befehl unverschlüsselt.",
    omemo_off: "OMEMO ist bei diesem Bot ausgeschaltet.",
    decrypt_failed: "✗ Ihre OMEMO-Nachricht konnte nicht entschlüsselt werden ({error}). Senden Sie sie erneut; \
                     schlägt das fehl, aktualisieren Sie die OMEMO-Schlüssel dieses Kontakts.",
    untrusted_key: "✗ Der OMEMO-Schlüssel dieses Geräts ist für den Bot nicht vertrauenswürdig:\n`{fp}`\n\
                    Damit er vertraut wird, senden Sie diese Zeile an den Administrator:",
    internal_error: "interner Fehler",
    encrypt_failed: "✗ Die Antwort konnte nicht verschlüsselt werden (Details im Log des Bots).",
    bot_device: "OMEMO-Gerät des Bots {id}\nFingerabdruck: `{fp}`\n",
    your_devices: "\nIhre Geräte ({n}):",
    key_pinned: "angeheftet",
    key_blind: "vertraut (nicht angeheftet)",
    key_untrusted: "*NICHT vertraut*",
    no_session: "noch keine Sitzung",
    devices_title: "Ihre verbundenen Geräte ({n}):",
    devices_none: "Keine Geräte verbunden.",
    this_device: "dieses Gerät",
    online_for: "verbunden seit {time}",
    devices_footer: "Prüfen Sie diese Liste ab und zu. Wenn Sie ein Gerät nicht kennen, melden Sie es mit `/logout <nummer>` ab und legen Sie mit `/resetlink` ein neues Passwort fest: sonst verbindet es sich mit dem gespeicherten Passwort wieder.",
    logout_args: "<nummer|gerät>",
    logout_done: "✓ Abgemeldet: {device}. Hat es Ihr Passwort gespeichert, verbindet es sich wieder; um es auszusperren, legen Sie mit /resetlink ein neues Passwort fest.",
    logout_current: "{device} ist das Gerät, von dem Sie gerade schreiben. Um es trotzdem abzumelden:\n`/logout {arg} confirm`",
    no_such_device: "✗ Kein solches Gerät. Senden Sie /devices für die Liste.",
    storage: "Nachrichten in Ihrem Serverarchiv: {mam}\nNachrichten, die auf Zustellung warten: {offline}",
    delete_history_ask: "Damit werden alle Ihre Nachrichten aus dem Serverarchiv gelöscht. Kopien auf Ihren Geräten bleiben erhalten. Zum Fortfahren:\n`/delete_history confirm`",
    history_deleted: "✓ Ihr Nachrichtenarchiv auf dem Server wurde gelöscht.",
    lang_set: "✓ Sprache: Deutsch.",
    unknown_language: "✗ Unbekannte Sprache. Möglich sind: EN, FR, GE, PL, RU, UA.",
    motd_none: "Keine Nachricht des Tages.",
    failed: "✗ Das hat nicht geklappt. Bitte wenden Sie sich an den Administrator.",
    days: "Tg.",
    privacy: "*Datenschutz und Speicherdauer auf {domain}*\n\n*Nachrichten*\n• Archivierte Nachrichten (auch in Gruppenchats) werden nach {messages} Tagen gelöscht.\n• Nachrichten, die auf einen Offline-Kontakt warten, werden nach {messages} Tagen gelöscht.\n• OMEMO-verschlüsselte Nachrichten werden verschlüsselt gespeichert: Der Server kann sie nicht lesen.\n  https://de.wikipedia.org/wiki/OMEMO\n\n*Dateien*\n• Hochgeladene Dateien (Bilder, Sprachnachrichten, …; je höchstens {quota} MB) werden nach {files} Tagen gelöscht.\n\n*Konten*\n• Ein Konto, das {accounts} Tage nicht genutzt wird, wird mit allen Daten gelöscht: Kontakte, Profil, Nachrichten.\n• Gruppenchats, die {rooms} Tage nicht genutzt werden, werden gelöscht.\n• Registrierungen für Push-Benachrichtigungen werden nach {messages} Tagen gelöscht.\n• Passwörter werden nur als gesalzene Hashes (SCRAM) gespeichert, nie im Klartext.\n  https://en.wikipedia.org/wiki/Salted_Challenge_Response_Authentication_Mechanism\n• Einladungs- und Passwort-Links laufen nach 5 Tagen ab und werden dann gelöscht.\n\n*Logs und Sicherheit*\n• Server-Logs (Anmeldungen, IP-Adressen) werden spätestens nach 14 Tagen gelöscht.\n• Sicherheitsaufzeichnungen (gesperrte Adressen, verdächtige Anmeldungen und die Gründe) werden bis zu {security} Tage aufbewahrt.\n• Beide dienen nur der Sicherheit: dem Schutz Ihres Kontos, etwa davor, dass jemand Ihr Passwort errät, und dem Schutz des gesamten Servers vor Angriffen.\n• Einmal pro Woche erhält der Administrator einen verschlüsselten Bericht über die gesperrten Adressen und was sie getan haben, ohne Kontonamen, um die Angriffe den Netzen zu melden, aus denen sie kommen. Der Server speichert ihn nur verschlüsselt, höchstens {files} Tage.\n\n*Dieser Bot*\n• Chats mit dem Bot werden nicht archiviert.\n• Der Bot speichert nur, wer ihn nutzen darf, die Sprache jedes Nutzers und Missbrauchsmeldungen; diese löscht er nach {reports} Tagen, ebenso alles zu gelöschten Konten.\n• Sein Log hält fest, welche Befehle genutzt wurden, nie deren Inhalt, und wird spätestens nach 14 Tagen gelöscht.",
    export_title: "*Ihre Daten auf {domain}*\n{jid}, Stand {date}",
    export_account: "*Konto*",
    export_last: "Letzte Anmeldung oder Abmeldung: {time}",
    export_online: "gerade online",
    export_profile: "*Profil (vCard)*",
    vcard_labels: ["Vollständiger Name", "Spitzname", "Geburtstag", "Website", "Über mich", "E-Mail", "Telefon"],
    export_contacts: "*Kontakte ({n})*",
    export_rooms: "*Gruppenchats ({n})*",
    export_devices: "*Verbundene Geräte ({n})*",
    export_messages: "*Gespeicherte Nachrichten*",
    export_invites: "*Von Ihnen erstellte Einladungen ({n})*",
    invite_open: "offen",
    invite_used: "genutzt",
    invite_expired: "abgelaufen",
    export_bot: "*Dieser Bot*",
    export_language: "Sprache: {lang}",
    export_reports_by: "Ihre Missbrauchsmeldungen ({n}):",
    export_reports_about: "Meldungen über Sie: {n}",
    export_none: "keine",
    export_footer: "Nicht enthalten: die Nachrichten selbst (Ihr Client lädt sie aus dem Serverarchiv, das sie {messages} Tage aufbewahrt), von Ihnen gesendete Dateien (in Ihren Chats verlinkt, {files} Tage aufbewahrt) und Server-Logs.",
    export_file: "📎 {file} ({kb} KB): die vollständige Kopie Ihrer Daten, archivierte Nachrichten eingeschlossen, als JSON. Verschlüsselt: Der Server löscht seine (verschlüsselte) Kopie nach {days} Tagen.",
    export_file_needs_omemo: "Die vollständige Kopie als Datei wird nur in einem mit OMEMO verschlüsselten Chat gesendet. Schalten Sie OMEMO für diesen Chat ein und senden Sie /export erneut.",
    export_file_failed: "✗ Die Datei mit der vollständigen Kopie konnte nicht gesendet werden. Bitte versuchen Sie es später noch einmal.",

    flag: "🇩🇪",
    tz: chrono_tz::Europe::Berlin,
    today: "Heute",
    tomorrow: "Morgen",
    weekdays: ["Mo", "Di", "Mi", "Do", "Fr", "Sa", "So"],
    range_from: "von",
    range_to: "bis",
    time_separator: ":",
    maintenance_subject: "Serverwartung",
    maintenance_notice: "Der Server ist wegen Wartungsarbeiten nicht erreichbar, {range}.",
    restart_notice: "Der Server startet in {minutes} Min. neu und ist etwa eine Minute nicht erreichbar.",
    warning_subject: "Wichtige Mitteilung",
};

pub const RU: Texts = Texts {
    help: "\
`/invite` — пригласить кого-нибудь на этот сервер
`/resetlink` — ссылка для установки нового пароля вашей учётной записи
`/devices` — ваши подключённые устройства
`/logout <номер|устройство>` — отключить одно из ваших устройств
`/storage` — ваши сообщения, хранящиеся на сервере
`/delete_history confirm` — удалить архив ваших сообщений на сервере
`/motd` — сообщение дня
`/lang <EN|FR|GE|PL|RU|UA>` — язык ответов бота
`/abuse <пользователь> [причина]` — пожаловаться на пользователя
`/export` — копия ваших данных на сервере
`/privacy` — как долго сервер хранит ваши данные
`/omemo` — показать отпечатки OMEMO
`/help` — показать эту справку

Вопросы или проблемы? Напишите администратору: {admin}",
    not_a_command: "Команды должны начинаться с '/'. Введите '/help'.",
    parse_error: "Ошибка разбора команды: нет закрывающей кавычки",
    no_command: "Команда не указана. Введите '/help'.",
    unknown_command: "Неизвестная команда: '{cmd}'. Введите '/help'.",
    usage: "Использование",
    example: "Пример",
    abuse_args: "<пользователь> [причина]",
    abuse_example: "john 'Спам-аккаунт'",
    invalid_username: "✗ Неверное имя пользователя.",
    invite: "Чтобы пригласить кого-нибудь, откройте\n{url}\nвойдите со своей учётной записью и создайте приглашение. \
             Отправьте полученную ссылку: по ней можно зарегистрировать учётную запись на этом сервере.",
    reset_link: "✓ Ссылка для установки нового пароля вашей учётной записи (одноразовая; действует столько же, сколько приглашение, \
                 по умолчанию 5 дней):",
    reset_link_xmpp: "Для XMPP-клиентов, которые это поддерживают:",
    reset_link_failed: "✗ Не удалось создать ссылку для сброса пароля. Обратитесь к администратору.",
    cannot_report: "✗ На '{user}' нельзя пожаловаться.",
    report_once: "✗ На одного пользователя можно пожаловаться только один раз.",
    report_accepted: "✓ Ваша жалоба принята.",
    report_failed: "✗ Не удалось сохранить жалобу. Сообщите администратору.",
    not_run_late: "✗ Не выполнено: эта команда отправлена {time} назад и дошла до бота только сейчас. \
                   Отправьте её ещё раз, чтобы выполнить.",
    minutes: "мин",
    hours: "ч",
    omemo_required: "✗ Этот бот принимает только сообщения, зашифрованные OMEMO. Включите OMEMO в этом чате.",
    omemo_off_send_plain: "✗ OMEMO на этом боте отключено; отправьте команду без шифрования.",
    omemo_off: "OMEMO на этом боте отключено.",
    decrypt_failed: "✗ Не удалось расшифровать ваше сообщение OMEMO ({error}). Отправьте его ещё раз; \
                     если не поможет, обновите ключи OMEMO этого контакта.",
    untrusted_key: "✗ Бот не доверяет ключу OMEMO этого устройства:\n`{fp}`\n\
                    Чтобы бот ему доверял, отправьте эту строку администратору:",
    internal_error: "внутренняя ошибка",
    encrypt_failed: "✗ Не удалось зашифровать ответ (подробности в журнале бота).",
    bot_device: "Устройство OMEMO бота {id}\nОтпечаток: `{fp}`\n",
    your_devices: "\nВаши устройства ({n}):",
    key_pinned: "закреплён",
    key_blind: "доверенный (не закреплён)",
    key_untrusted: "*НЕ доверенный*",
    no_session: "сеанса пока нет",
    devices_title: "Ваши подключённые устройства ({n}):",
    devices_none: "Нет подключённых устройств.",
    this_device: "это устройство",
    online_for: "в сети {time}",
    devices_footer: "Время от времени проверяйте этот список. Если вы не узнаёте устройство, отключите его командой `/logout <номер>` и задайте новый пароль через `/resetlink`: иначе оно снова подключится с сохранённым паролем.",
    logout_args: "<номер|устройство>",
    logout_done: "✓ Отключено: {device}. Если на нём сохранён ваш пароль, оно подключится снова; чтобы закрыть ему доступ, задайте новый пароль через /resetlink.",
    logout_current: "{device} — устройство, с которого вы сейчас пишете. Чтобы всё равно отключить его:\n`/logout {arg} confirm`",
    no_such_device: "✗ Такого устройства нет. Отправьте /devices, чтобы увидеть список.",
    storage: "Сообщений в вашем архиве на сервере: {mam}\nСообщений, ожидающих доставки: {offline}",
    delete_history_ask: "Это удалит все ваши сообщения из архива на сервере. Копии на ваших устройствах останутся. Чтобы продолжить:\n`/delete_history confirm`",
    history_deleted: "✓ Архив ваших сообщений на сервере удалён.",
    lang_set: "✓ Язык: русский.",
    unknown_language: "✗ Неизвестный язык. Доступны: EN, FR, GE, PL, RU, UA.",
    motd_none: "Сообщения дня нет.",
    failed: "✗ Не получилось. Обратитесь к администратору.",
    days: "д",
    privacy: "*Конфиденциальность и хранение данных на {domain}*\n\n*Сообщения*\n• Архивные сообщения (в том числе в групповых чатах) удаляются через {messages} дн.\n• Сообщения, ожидающие контакт не в сети, удаляются через {messages} дн.\n• Сообщения со сквозным шифрованием OMEMO хранятся в зашифрованном виде: сервер не может их прочитать.\n  https://ru.wikipedia.org/wiki/OMEMO\n\n*Файлы*\n• Загруженные файлы (изображения, голосовые сообщения, …; каждый не больше {quota} МБ) удаляются через {files} дн.\n\n*Учётные записи*\n• Учётная запись, которой не пользовались {accounts} дн., удаляется вместе со всеми данными: контактами, профилем, сообщениями.\n• Групповые чаты, которыми не пользовались {rooms} дн., удаляются.\n• Регистрации для push-уведомлений удаляются через {messages} дн.\n• Пароли хранятся только в виде хешей с солью (механизм аутентификации SCRAM), никогда в открытом виде.\n  https://ru.wikipedia.org/wiki/SCRAM\n• Ссылки-приглашения и ссылки для сброса пароля действуют 5 дней, затем удаляются.\n\n*Журналы и безопасность*\n• Журналы сервера (входы, IP-адреса) удаляются не позже чем через 14 дней.\n• Записи системы безопасности (заблокированные адреса, подозрительные входы и причины) хранятся до {security} дн.\n• И то и другое используется только для безопасности: чтобы защитить вашу учётную запись, например от подбора пароля, и весь сервер — от атак.\n• Раз в неделю администратор получает зашифрованный отчёт о заблокированных адресах и их действиях, без имён учётных записей, чтобы сообщать об атаках в сети, из которых они идут. Сервер хранит его только в зашифрованном виде, не дольше {files} дн.\n\n*Этот бот*\n• Переписка с ботом не архивируется.\n• Бот хранит только список тех, кому он доступен, язык каждого пользователя и жалобы; жалобы он удаляет через {reports} дн., а всё об удалённых учётных записях — сразу.\n• В его журнале отмечается, какие команды использовались, но не их содержимое; журнал удаляется не позже чем через 14 дней.",
    export_title: "*Ваши данные на {domain}*\n{jid}, на {date}",
    export_account: "*Учётная запись*",
    export_last: "Последний вход или выход: {time}",
    export_online: "сейчас в сети",
    export_profile: "*Профиль (vCard)*",
    vcard_labels: ["Полное имя", "Псевдоним", "Дата рождения", "Сайт", "О себе", "Эл. почта", "Телефон"],
    export_contacts: "*Контакты ({n})*",
    export_rooms: "*Групповые чаты ({n})*",
    export_devices: "*Подключённые устройства ({n})*",
    export_messages: "*Хранящиеся сообщения*",
    export_invites: "*Созданные вами приглашения ({n})*",
    invite_open: "действует",
    invite_used: "использовано",
    invite_expired: "истекло",
    export_bot: "*Этот бот*",
    export_language: "Язык: {lang}",
    export_reports_by: "Ваши жалобы ({n}):",
    export_reports_about: "Жалоб на вас: {n}",
    export_none: "нет",
    export_footer: "Не включено: сами сообщения (ваш клиент загружает их из архива на сервере, где они хранятся {messages} дн.), отправленные вами файлы (ссылки на них есть в ваших чатах, хранятся {files} дн.) и журналы сервера.",
    export_file: "📎 {file} ({kb} КБ): полная копия ваших данных, включая архив сообщений, в формате JSON. Зашифрована: сервер удаляет свою (зашифрованную) копию через {days} дн.",
    export_file_needs_omemo: "Полная копия в виде файла отправляется только в чате, зашифрованном OMEMO. Включите OMEMO для этого чата и отправьте /export ещё раз.",
    export_file_failed: "✗ Не удалось отправить файл с полной копией. Попробуйте позже.",

    flag: "🇷🇺",
    tz: chrono_tz::Europe::Moscow,
    today: "Сегодня",
    tomorrow: "Завтра",
    weekdays: ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"],
    range_from: "с",
    range_to: "по",
    time_separator: ":",
    maintenance_subject: "Технические работы",
    maintenance_notice: "Сервер будет недоступен в связи с техническими работами {range}.",
    restart_notice: "Сервер перезапустится через {minutes} мин, примерно на минуту.",
    warning_subject: "Важное сообщение",
};

pub const UK: Texts = Texts {
    help: "\
`/invite` — запросити когось на цей сервер
`/resetlink` — посилання для встановлення нового пароля вашого облікового запису
`/devices` — ваші підключені пристрої
`/logout <номер|пристрій>` — відключити один із ваших пристроїв
`/storage` — ваші повідомлення, що зберігаються на сервері
`/delete_history confirm` — видалити архів ваших повідомлень на сервері
`/motd` — повідомлення дня
`/lang <EN|FR|GE|PL|RU|UA>` — мова відповідей бота
`/abuse <користувач> [причина]` — поскаржитися на користувача
`/export` — копія ваших даних на сервері
`/privacy` — як довго сервер зберігає ваші дані
`/omemo` — показати відбитки OMEMO
`/help` — показати цю довідку

Питання чи проблеми? Напишіть адміністраторові: {admin}",
    not_a_command: "Команди мають починатися з '/'. Введіть '/help'.",
    parse_error: "Помилка розбору команди: немає закривальної лапки",
    no_command: "Команду не вказано. Введіть '/help'.",
    unknown_command: "Невідома команда: '{cmd}'. Введіть '/help'.",
    usage: "Використання",
    example: "Приклад",
    abuse_args: "<користувач> [причина]",
    abuse_example: "john 'Спам-акаунт'",
    invalid_username: "✗ Неправильне ім'я користувача.",
    invite: "Щоб запросити когось, відкрийте\n{url}\nувійдіть зі своїм обліковим записом і створіть запрошення. \
             Надішліть отримане посилання: за ним можна зареєструвати обліковий запис на цьому сервері.",
    reset_link: "✓ Посилання для встановлення нового пароля вашого облікового запису (одноразове; діє стільки ж, скільки запрошення, \
                 типово 5 днів):",
    reset_link_xmpp: "Для XMPP-клієнтів, які це підтримують:",
    reset_link_failed: "✗ Не вдалося створити посилання для скидання пароля. Зверніться до адміністратора.",
    cannot_report: "✗ На '{user}' не можна поскаржитися.",
    report_once: "✗ На одного користувача можна поскаржитися лише один раз.",
    report_accepted: "✓ Вашу скаргу прийнято.",
    report_failed: "✗ Не вдалося зберегти скаргу. Повідомте адміністратора.",
    not_run_late: "✗ Не виконано: цю команду надіслано {time} тому, і вона дійшла до бота лише зараз. \
                   Надішліть її ще раз, щоб виконати.",
    minutes: "хв",
    hours: "год",
    omemo_required: "✗ Цей бот приймає лише повідомлення, зашифровані OMEMO. Увімкніть OMEMO в цьому чаті.",
    omemo_off_send_plain: "✗ OMEMO на цьому боті вимкнено; надішліть команду без шифрування.",
    omemo_off: "OMEMO на цьому боті вимкнено.",
    decrypt_failed: "✗ Не вдалося розшифрувати ваше повідомлення OMEMO ({error}). Надішліть його ще раз; \
                     якщо не допоможе, оновіть ключі OMEMO цього контакту.",
    untrusted_key: "✗ Бот не довіряє ключу OMEMO цього пристрою:\n`{fp}`\n\
                    Щоб бот йому довіряв, надішліть цей рядок адміністраторові:",
    internal_error: "внутрішня помилка",
    encrypt_failed: "✗ Не вдалося зашифрувати відповідь (подробиці в журналі бота).",
    bot_device: "Пристрій OMEMO бота {id}\nВідбиток: `{fp}`\n",
    your_devices: "\nВаші пристрої ({n}):",
    key_pinned: "закріплений",
    key_blind: "довірений (не закріплений)",
    key_untrusted: "*НЕ довірений*",
    no_session: "сеансу ще немає",
    devices_title: "Ваші підключені пристрої ({n}):",
    devices_none: "Немає підключених пристроїв.",
    this_device: "цей пристрій",
    online_for: "в мережі {time}",
    devices_footer: "Час від часу перевіряйте цей список. Якщо ви не впізнаєте пристрій, відключіть його командою `/logout <номер>` і встановіть новий пароль через `/resetlink`: інакше він знову під'єднається зі збереженим паролем.",
    logout_args: "<номер|пристрій>",
    logout_done: "✓ Відключено: {device}. Якщо на ньому збережено ваш пароль, він під'єднається знову; щоб закрити йому доступ, встановіть новий пароль через /resetlink.",
    logout_current: "{device} — пристрій, з якого ви зараз пишете. Щоб усе одно відключити його:\n`/logout {arg} confirm`",
    no_such_device: "✗ Такого пристрою немає. Надішліть /devices, щоб побачити список.",
    storage: "Повідомлень у вашому архіві на сервері: {mam}\nПовідомлень, що очікують доставки: {offline}",
    delete_history_ask: "Це видалить усі ваші повідомлення з архіву на сервері. Копії на ваших пристроях залишаться. Щоб продовжити:\n`/delete_history confirm`",
    history_deleted: "✓ Архів ваших повідомлень на сервері видалено.",
    lang_set: "✓ Мова: українська.",
    unknown_language: "✗ Невідома мова. Доступні: EN, FR, GE, PL, RU, UA.",
    motd_none: "Повідомлення дня немає.",
    failed: "✗ Не вдалося. Зверніться до адміністратора.",
    days: "д",
    privacy: "*Конфіденційність і зберігання даних на {domain}*\n\n*Повідомлення*\n• Архівні повідомлення (зокрема в групових чатах) видаляються через {messages} дн.\n• Повідомлення, що очікують контакт поза мережею, видаляються через {messages} дн.\n• Повідомлення з наскрізним шифруванням OMEMO зберігаються в зашифрованому вигляді: сервер не може їх прочитати.\n  https://uk.wikipedia.org/wiki/OMEMO\n\n*Файли*\n• Завантажені файли (зображення, голосові повідомлення, …; кожен не більше {quota} МБ) видаляються через {files} дн.\n\n*Облікові записи*\n• Обліковий запис, яким не користувалися {accounts} дн., видаляється разом з усіма даними: контактами, профілем, повідомленнями.\n• Групові чати, якими не користувалися {rooms} дн., видаляються.\n• Реєстрації для push-сповіщень видаляються через {messages} дн.\n• Паролі зберігаються лише у вигляді гешів із сіллю (механізм автентифікації SCRAM), ніколи у відкритому вигляді.\n  https://uk.wikipedia.org/wiki/SCRAM\n• Посилання-запрошення та посилання для скидання пароля діють 5 днів, потім видаляються.\n\n*Журнали та безпека*\n• Журнали сервера (входи, IP-адреси) видаляються не пізніше ніж через 14 днів.\n• Записи системи безпеки (заблоковані адреси, підозрілі входи та причини) зберігаються до {security} дн.\n• І те, й інше використовується лише для безпеки: щоб захистити ваш обліковий запис, наприклад від підбору пароля, і весь сервер — від атак.\n• Раз на тиждень адміністратор отримує зашифрований звіт про заблоковані адреси та їхні дії, без імен облікових записів, щоб повідомляти про атаки мережам, з яких вони надходять. Сервер зберігає його лише в зашифрованому вигляді, не довше {files} дн.\n\n*Цей бот*\n• Листування з ботом не архівується.\n• Бот зберігає лише перелік тих, кому він доступний, мову кожного користувача та скарги; скарги він видаляє через {reports} дн., а все про видалені облікові записи — одразу.\n• У його журналі видно, які команди використовувалися, але не їхній вміст; журнал видаляється не пізніше ніж через 14 днів.",
    export_title: "*Ваші дані на {domain}*\n{jid}, станом на {date}",
    export_account: "*Обліковий запис*",
    export_last: "Останній вхід або вихід: {time}",
    export_online: "зараз у мережі",
    export_profile: "*Профіль (vCard)*",
    vcard_labels: ["Повне ім'я", "Псевдонім", "Дата народження", "Сайт", "Про себе", "Ел. пошта", "Телефон"],
    export_contacts: "*Контакти ({n})*",
    export_rooms: "*Групові чати ({n})*",
    export_devices: "*Підключені пристрої ({n})*",
    export_messages: "*Збережені повідомлення*",
    export_invites: "*Створені вами запрошення ({n})*",
    invite_open: "діє",
    invite_used: "використано",
    invite_expired: "закінчилося",
    export_bot: "*Цей бот*",
    export_language: "Мова: {lang}",
    export_reports_by: "Ваші скарги ({n}):",
    export_reports_about: "Скарг на вас: {n}",
    export_none: "немає",
    export_footer: "Не включено: самі повідомлення (ваш клієнт завантажує їх з архіву на сервері, де вони зберігаються {messages} дн.), надіслані вами файли (посилання на них є у ваших чатах, зберігаються {files} дн.) і журнали сервера.",
    export_file: "📎 {file} ({kb} КБ): повна копія ваших даних, включно з архівом повідомлень, у форматі JSON. Зашифрована: сервер видаляє свою (зашифровану) копію через {days} дн.",
    export_file_needs_omemo: "Повна копія у вигляді файлу надсилається лише в чаті, зашифрованому OMEMO. Увімкніть OMEMO для цього чату й надішліть /export ще раз.",
    export_file_failed: "✗ Не вдалося надіслати файл із повною копією. Спробуйте пізніше.",

    flag: "🇺🇦",
    tz: chrono_tz::Europe::Kyiv,
    today: "Сьогодні",
    tomorrow: "Завтра",
    weekdays: ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Нд"],
    range_from: "з",
    range_to: "по",
    time_separator: ":",
    maintenance_subject: "Технічні роботи",
    maintenance_notice: "Сервер буде недоступний у зв'язку з технічними роботами {range}.",
    restart_notice: "Сервер перезапуститься через {minutes} хв, приблизно на хвилину.",
    warning_subject: "Важливе повідомлення",
};

pub const PL: Texts = Texts {
    help: "\
`/invite` — zaproś kogoś na ten serwer
`/resetlink` — link do ustawienia nowego hasła do Twojego konta
`/devices` — Twoje połączone urządzenia
`/logout <numer|urządzenie>` — rozłącz jedno z Twoich urządzeń
`/storage` — Twoje wiadomości przechowywane na serwerze
`/delete_history confirm` — usuń archiwum Twoich wiadomości na serwerze
`/motd` — bieżąca wiadomość dnia
`/lang <EN|FR|GE|PL|RU|UA>` — język odpowiedzi bota
`/abuse <użytkownik> [powód]` — zgłoś użytkownika
`/export` — kopia Twoich danych na serwerze
`/privacy` — jak długo serwer przechowuje Twoje dane
`/omemo` — pokaż odciski kluczy OMEMO
`/help` — pokaż tę pomoc

Pytania lub problemy? Napisz do administratora: {admin}",
    not_a_command: "Polecenia muszą zaczynać się od '/'. Wpisz '/help'.",
    parse_error: "Błąd składni polecenia: brak zamykającego cudzysłowu",
    no_command: "Nie podano polecenia. Wpisz '/help'.",
    unknown_command: "Nieznane polecenie: '{cmd}'. Wpisz '/help'.",
    usage: "Użycie",
    example: "Przykład",
    abuse_args: "<użytkownik> [powód]",
    abuse_example: "jan 'Konto spamowe'",
    invalid_username: "✗ Nieprawidłowa nazwa użytkownika.",
    invite: "Aby kogoś zaprosić, otwórz\n{url}\nzaloguj się swoim kontem i utwórz zaproszenie. Wyślij tej osobie otrzymany link: \
             pozwala on założyć konto na tym serwerze.",
    reset_link: "✓ Link do ustawienia nowego hasła do Twojego konta (jednorazowy; ważny tyle co zaproszenie, domyślnie 5 dni):",
    reset_link_xmpp: "Dla klientów XMPP, które to obsługują:",
    reset_link_failed: "✗ Nie udało się utworzyć linku. Zwróć się do administratora.",
    cannot_report: "✗ Nie można zgłosić '{user}'.",
    report_once: "✗ Tego samego użytkownika można zgłosić tylko raz.",
    report_accepted: "✓ Twoje zgłoszenie zostało przyjęte.",
    report_failed: "✗ Nie udało się zapisać zgłoszenia. Powiadom administratora.",
    not_run_late: "✗ Nie wykonano: to polecenie wysłano {time} temu i dotarło do bota dopiero teraz. Wyślij je ponownie, aby je wykonać.",
    minutes: "min",
    hours: "godz.",
    omemo_required: "✗ Ten bot przyjmuje tylko wiadomości zaszyfrowane OMEMO. Włącz OMEMO w tym czacie.",
    omemo_off_send_plain: "✗ OMEMO jest wyłączone w tym bocie; wyślij polecenie bez szyfrowania.",
    omemo_off: "OMEMO jest wyłączone w tym bocie.",
    decrypt_failed: "✗ Nie udało się odszyfrować Twojej wiadomości OMEMO ({error}). Wyślij ją ponownie; jeśli to nie pomoże, odśwież klucze OMEMO tego kontaktu.",
    untrusted_key: "✗ Bot nie ufa kluczowi OMEMO tego urządzenia:\n`{fp}`\nAby został zaufany, wyślij administratorowi ten wiersz:",
    internal_error: "błąd wewnętrzny",
    encrypt_failed: "✗ Nie udało się zaszyfrować odpowiedzi (szczegóły w dzienniku bota).",
    bot_device: "Urządzenie OMEMO bota {id}\nOdcisk klucza: `{fp}`\n",
    your_devices: "\nTwoje urządzenia ({n}):",
    key_pinned: "przypięty",
    key_blind: "zaufany (nieprzypięty)",
    key_untrusted: "*NIEZAUFANY*",
    no_session: "brak sesji",
    devices_title: "Twoje połączone urządzenia ({n}):",
    devices_none: "Żadne urządzenie nie jest połączone.",
    this_device: "to urządzenie",
    online_for: "online od {time}",
    devices_footer: "Sprawdzaj tę listę od czasu do czasu. Jeśli nie rozpoznajesz urządzenia, rozłącz je poleceniem `/logout <numer>` i ustaw nowe hasło przez `/resetlink`: inaczej połączy się ponownie zapisanym hasłem.",
    logout_args: "<numer|urządzenie>",
    logout_done: "✓ Rozłączono: {device}. Jeśli ma zapisane Twoje hasło, połączy się ponownie; aby je zablokować, ustaw nowe hasło przez /resetlink.",
    logout_current: "{device} to urządzenie, z którego piszesz. Aby mimo to je rozłączyć:\n`/logout {arg} confirm`",
    no_such_device: "✗ Nie ma takiego urządzenia. Wyślij /devices, aby zobaczyć listę.",
    storage: "Wiadomości w archiwum na serwerze: {mam}\nWiadomości czekające na doręczenie: {offline}",
    delete_history_ask: "To usuwa wszystkie Twoje wiadomości z archiwum na serwerze. Kopie na Twoich urządzeniach zostają. Aby kontynuować:\n`/delete_history confirm`",
    history_deleted: "✓ Archiwum Twoich wiadomości na serwerze zostało usunięte.",
    lang_set: "✓ Język: polski.",
    unknown_language: "✗ Nieznany język. Dostępne: EN, FR, GE, PL, RU, UA.",
    motd_none: "Brak wiadomości dnia.",
    failed: "✗ Nie udało się. Zwróć się do administratora.",
    days: "dni",
    privacy: "*Prywatność i przechowywanie danych na {domain}*\n\n*Wiadomości*\n• Zarchiwizowane wiadomości (także z czatów grupowych) są usuwane po {messages} dniach.\n• Wiadomości czekające na kontakt, który jest offline, są usuwane po {messages} dniach.\n• Wiadomości zaszyfrowane OMEMO są przechowywane w postaci zaszyfrowanej: serwer nie może ich odczytać.\n  https://pl.wikipedia.org/wiki/OMEMO\n\n*Pliki*\n• Przesłane pliki (zdjęcia, wiadomości głosowe, …; do {quota} MB każdy) są usuwane po {files} dniach.\n\n*Konta*\n• Konto nieużywane przez {accounts} dni jest usuwane wraz ze wszystkimi danymi: kontaktami, profilem, wiadomościami.\n• Czaty grupowe nieużywane przez {rooms} dni są usuwane.\n• Rejestracje powiadomień push są usuwane po {messages} dniach.\n• Hasła są przechowywane wyłącznie jako solone skróty (SCRAM), nigdy jawnym tekstem.\n  https://en.wikipedia.org/wiki/Salted_Challenge_Response_Authentication_Mechanism\n• Linki z zaproszeniami i do resetu hasła wygasają po 5 dniach, a potem są usuwane.\n\n*Dzienniki i bezpieczeństwo*\n• Dzienniki serwera (logowania, adresy IP) są usuwane najpóźniej po 14 dniach.\n• Zapisy bezpieczeństwa (zablokowane adresy, podejrzane logowania i ich przyczyny) są przechowywane do {security} dni.\n• Jedne i drugie służą wyłącznie bezpieczeństwu: ochronie Twojego konta, na przykład przed zgadywaniem hasła, i całego serwera przed atakami.\n• Raz w tygodniu administrator otrzymuje zaszyfrowany raport o zablokowanych adresach i ich działaniach, bez nazw kont, aby zgłaszać ataki sieciom, z których pochodzą. Serwer przechowuje go wyłącznie zaszyfrowany, najwyżej {files} dni.\n\n*Ten bot*\n• Czaty z botem nie są archiwizowane.\n• Bot przechowuje tylko, kto może z niego korzystać, język każdego użytkownika i zgłoszenia nadużyć, które usuwa po {reports} dniach, podobnie jak wszystko o usuniętych kontach.\n• Jego dziennik zapisuje, których poleceń użyto, nigdy ich treści, i jest usuwany najpóźniej po 14 dniach.",
    export_title: "*Twoje dane na {domain}*\n{jid}, stan na {date}",
    export_account: "*Konto*",
    export_last: "Ostatnie logowanie lub wylogowanie: {time}",
    export_online: "teraz online",
    export_profile: "*Profil (vCard)*",
    vcard_labels: ["Imię i nazwisko", "Pseudonim", "Data urodzenia", "Strona WWW", "O mnie", "E-mail", "Telefon"],
    export_contacts: "*Kontakty ({n})*",
    export_rooms: "*Czaty grupowe ({n})*",
    export_devices: "*Połączone urządzenia ({n})*",
    export_messages: "*Przechowywane wiadomości*",
    export_invites: "*Utworzone przez Ciebie zaproszenia ({n})*",
    invite_open: "otwarte",
    invite_used: "wykorzystane",
    invite_expired: "wygasłe",
    export_bot: "*Ten bot*",
    export_language: "Język: {lang}",
    export_reports_by: "Twoje zgłoszenia nadużyć ({n}):",
    export_reports_about: "Zgłoszenia dotyczące Ciebie: {n}",
    export_none: "brak",
    export_footer: "Nie zawiera: samych wiadomości (Twój klient pobiera je z archiwum na serwerze, które przechowuje je {messages} dni), wysłanych przez Ciebie plików (linki są w Twoich czatach, przechowywane {files} dni) ani dzienników serwera.",
    export_file: "📎 {file} ({kb} KB): pełna kopia Twoich danych, łącznie z archiwum wiadomości, w formacie JSON. Zaszyfrowana: serwer usuwa swoją (zaszyfrowaną) kopię po {days} dniach.",
    export_file_needs_omemo: "Pełna kopia w postaci pliku jest wysyłana tylko w czacie zaszyfrowanym OMEMO. Włącz OMEMO w tym czacie i wyślij /export ponownie.",
    export_file_failed: "✗ Nie udało się wysłać pliku z pełną kopią. Spróbuj ponownie później.",

    flag: "🇵🇱",
    tz: chrono_tz::Europe::Warsaw,
    today: "Dziś",
    tomorrow: "Jutro",
    weekdays: ["Pn", "Wt", "Śr", "Cz", "Pt", "So", "Nd"],
    range_from: "od",
    range_to: "do",
    time_separator: ":",
    maintenance_subject: "Prace konserwacyjne",
    maintenance_notice: "Serwer będzie niedostępny z powodu prac konserwacyjnych {range}.",
    restart_notice: "Serwer zostanie ponownie uruchomiony za {minutes} min, na około minutę.",
    warning_subject: "Ważna informacja",
};

/// "45 min", "3 h", "2 d", in the language's units.
pub fn duration(t: &Texts, secs: i64) -> String {
    if secs < 2 * 3600 {
        format!("{} {}", (secs / 60).max(1), t.minutes)
    } else if secs < 2 * 86400 {
        format!("{} {}", secs / 3600, t.hours)
    } else {
        format!("{} {}", secs / 86400, t.days)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        assert_eq!(Language::parse("fr"), Some(Language::Fr));
        assert_eq!(Language::parse("Ge"), Some(Language::De));
        assert_eq!(Language::parse("UA"), Some(Language::Uk));
        assert_eq!(Language::parse("de"), None, "German is GE");
        assert_eq!(Language::parse("E1"), None);
        assert_eq!(Language::parse("ENG"), None);
        for l in Language::ALL {
            assert_eq!(Language::parse(l.code()), Some(l));
        }
    }

    #[test]
    fn setting_codes() {
        use Language::*;
        assert_eq!(parse_languages("EN,FR,RU,UK"), Ok(vec![En, Fr, Ru, Uk]));
        assert_eq!(parse_languages(" pl, de ua; en,pl "), Ok(vec![Pl, De, Uk, En]), "aliases, any separator, no repeats");
        assert_eq!(parse_languages("GE"), Ok(vec![De]));
        assert!(parse_languages("EN,XX").unwrap_err().contains("'XX'"));
        assert!(parse_languages(" , ").is_err());
        assert_eq!(Language::parse("uk"), None, "in chat, Ukrainian stays UA");
        assert_eq!(Language::parse("pl"), Some(Pl));
    }

    /// Every language has the same placeholders, and commands are not translated.
    #[test]
    fn translations_are_complete() {
        let fields = |t: &Texts| {
            vec![
                t.unknown_command,
                t.invite,
                t.cannot_report,
                t.not_run_late,
                t.decrypt_failed,
                t.untrusted_key,
                t.bot_device,
                t.your_devices,
                t.help,
                t.devices_title,
                t.online_for,
                t.logout_done,
                t.logout_current,
                t.privacy,
                t.export_title,
                t.export_last,
                t.export_contacts,
                t.export_rooms,
                t.export_devices,
                t.export_invites,
                t.invite_used,
                t.export_language,
                t.export_reports_by,
                t.export_reports_about,
                t.export_footer,
                t.export_file,
                t.storage,
                t.maintenance_notice,
                t.restart_notice,
            ]
        };
        let placeholders = |s: &str| {
            let mut p: Vec<String> = s.split('{').skip(1).filter_map(|r| r.split_once('}')).map(|(n, _)| n.to_string()).collect();
            p.sort();
            p
        };
        let commands =
            |s: &str| s.split('`').filter(|w| w.starts_with('/')).map(|w| w.split(' ').next().unwrap().to_string()).collect::<Vec<_>>();
        for l in Language::ALL {
            let t = l.texts();
            for (en, other) in fields(&EN).into_iter().zip(fields(t)) {
                assert_eq!(placeholders(en), placeholders(other), "{l:?}: {other}");
            }
            assert_eq!(commands(EN.help), commands(t.help), "{l:?}");
            assert!(!t.usage.is_empty() && !t.example.is_empty() && !t.minutes.is_empty());
        }
        assert_eq!(duration(&RU, 3 * 3600 + 5), "3 ч");
        assert_eq!(duration(&EN, 600), "10 min");
        assert_eq!(duration(&FR, 3 * 86400), "3 j");
    }
}
