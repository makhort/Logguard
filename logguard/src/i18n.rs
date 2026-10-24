//! Translations (English, French, German, Polish, Russian, Ukrainian) of the security notices sent to XMPP users
//! (`[notify] language`, `[notify.languages]`). Admin messages, logs and the TUI stay in English.
//!
//! Notices are rendered from their facts (`UserNotice`) in the recipient's language, so
//! numbers get proper plural forms (Polish, Russian and Ukrainian have three).

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::engine::Topic;
use crate::net::Net;
use crate::time::{fmt_ts, Micros, SEC};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    #[serde(alias = "english")]
    En,
    #[serde(alias = "french", alias = "français", alias = "francais")]
    Fr,
    #[serde(alias = "german", alias = "deutsch")]
    De,
    #[serde(alias = "russian", alias = "русский")]
    Ru,
    #[serde(alias = "ukrainian", alias = "українська")]
    Uk,
    #[serde(alias = "polish", alias = "polski")]
    Pl,
}

/// What a user is told, as facts; rendered per language by `note`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UserNotice {
    /// Distributed password guessing against the account.
    AccountAttack { failures: u32, addresses: usize },
    /// An address was banned after failed logins; per qualified account (`ejabberd:alice@x`).
    BruteForce { ip: IpAddr, attempts: BTreeMap<String, u32> },
    /// Login right after suspicious activity from the same address.
    Compromise { ip: IpAddr, place: Option<String>, at: Micros },
    /// Login from a network the account hasn't used before.
    NewLogin { ip: IpAddr, place: Option<String>, network: Net, at: Micros },
}

/// Slavic plural category: 0 = one (1, 21, 31...), 1 = few (2-4, 22-24...), 2 = many.
fn slavic(n: u64) -> usize {
    match (n % 10, n % 100) {
        (1, r) if r != 11 => 0,
        (2..=4, r) if !(12..=14).contains(&r) => 1,
        _ => 2,
    }
}

/// Polish plural category: 0 = one (only 1), 1 = few (2-4, 22-24... but not 12-14), 2 = many
/// (0, 5-21, 25-31...: unlike Russian, 21 is "many").
fn polish(n: u64) -> usize {
    match (n, n % 10, n % 100) {
        (1, _, _) => 0,
        (_, 2..=4, r) if !(12..=14).contains(&r) => 1,
        _ => 2,
    }
}

/// `n` with the matching form: `forms` = [one, few, many] (English/French use one/many).
fn count(lang: Lang, n: u64, forms: [&str; 3]) -> String {
    let i = match lang {
        Lang::Ru | Lang::Uk => slavic(n),
        Lang::Pl => polish(n),
        Lang::En => usize::from(n != 1) * 2,
        Lang::Fr => usize::from(n > 1) * 2,
        Lang::De => usize::from(n != 1) * 2,
    };
    format!("{n} {}", forms[i])
}

/// After "около"/"близько" (+ genitive) only two forms exist: singular for 1, 21, 31...
fn genitive(n: u64, sg: &str, pl: &str) -> String {
    format!("{n} {}", if slavic(n) == 0 { sg } else { pl })
}

/// A ban length as a phrase that follows "for" ("for 6 hours", "на 6 часов").
pub fn duration(lang: Lang, us: Micros) -> String {
    let s = (us.max(0) / SEC) as u64;
    let (days, hours, minutes) = (s / 86_400, s % 86_400 / 3600, s % 3600 / 60);
    let unit = |n: u64, which: usize| -> String {
        // accusative after "на": час/часа/часов, but минуту/годину
        let forms: [[&str; 3]; 3] = match lang {
            Lang::En => [["day", "", "days"], ["hour", "", "hours"], ["minute", "", "minutes"]],
            Lang::Fr => [["jour", "", "jours"], ["heure", "", "heures"], ["minute", "", "minutes"]],
            Lang::De => [["Tag", "", "Tage"], ["Stunde", "", "Stunden"], ["Minute", "", "Minuten"]],
            Lang::Ru => [["день", "дня", "дней"], ["час", "часа", "часов"], ["минуту", "минуты", "минут"]],
            Lang::Uk => [["день", "дні", "днів"], ["годину", "години", "годин"], ["хвилину", "хвилини", "хвилин"]],
            // accusative after "na": godzinę, minutę
            Lang::Pl => [["dzień", "dni", "dni"], ["godzinę", "godziny", "godzin"], ["minutę", "minuty", "minut"]],
        };
        count(lang, n, forms[which])
    };
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(unit(days, 0));
    }
    if hours > 0 {
        parts.push(unit(hours, 1));
    }
    if minutes > 0 && days == 0 {
        parts.push(unit(minutes, 2));
    }
    if parts.is_empty() {
        parts.push(unit(1, 2));
    }
    parts.join(" ")
}

fn where_from(lang: Lang, ip: IpAddr, place: &Option<String>) -> String {
    match (place, lang) {
        (Some(p), _) => format!("{ip} ({p})"),
        (None, _) => ip.to_string(),
    }
}

/// The notice text. With `recipient` (a qualified account), a brute-force notice only
/// mentions that account: one user's message must not reveal others' account names.
pub fn note(n: &UserNotice, lang: Lang, recipient: Option<&str>) -> String {
    match n {
        UserNotice::AccountAttack { failures, addresses } => {
            let (f, a) = (u64::from(*failures), *addresses as u64);
            match lang {
                Lang::En => format!(
                    "Your account is the target of a password-guessing attack: about {f} failed login attempts \
                     from {a} different addresses in the last hour. None of them logged in."
                ),
                Lang::Fr => format!(
                    "Votre compte est la cible d'une attaque visant à deviner son mot de passe : environ {f} tentatives \
                     de connexion échouées depuis {a} adresses différentes au cours de la dernière heure. Aucune n'a abouti."
                ),
                Lang::De => format!(
                    "Ihr Konto ist das Ziel eines Angriffs, bei dem Passwörter erraten werden: etwa {f} fehlgeschlagene \
                     Anmeldeversuche von {a} verschiedenen Adressen in der letzten Stunde. Keiner davon war erfolgreich."
                ),
                Lang::Ru => format!(
                    "Ваша учётная запись стала целью атаки с подбором пароля: около {} входа с {} за последний час. \
                     Ни одна из них не была успешной.",
                    genitive(f, "неудачной попытки", "неудачных попыток"),
                    genitive(a, "разного адреса", "разных адресов")
                ),
                Lang::Uk => format!(
                    "Ваш обліковий запис став ціллю атаки з підбором пароля: близько {} входу з {} за останню годину. \
                     Жодна з них не була успішною.",
                    genitive(f, "невдалої спроби", "невдалих спроб"),
                    genitive(a, "різної адреси", "різних адрес")
                ),
                // after "około" and "z", the genitive: singular for 1 only
                Lang::Pl => format!(
                    "Twoje konto jest celem ataku polegającego na zgadywaniu hasła: około {} {} logowania z {} {} \
                     w ciągu ostatniej godziny. Żadna z nich się nie powiodła.",
                    f,
                    if f == 1 { "nieudanej próby" } else { "nieudanych prób" },
                    a,
                    if a == 1 { "adresu" } else { "różnych adresów" }
                ),
            }
        }
        UserNotice::BruteForce { ip, attempts } => attempts
            .iter()
            .filter(|(acct, _)| recipient.is_none_or(|r| r == acct.as_str()))
            .map(|(acct, n)| {
                let name = acct.split_once(':').map_or(acct.as_str(), |(_, a)| a);
                let n = u64::from(*n);
                match lang {
                    Lang::En => {
                        format!("{} on {name} came from {ip}.", count(lang, n, ["failed login attempt", "", "failed login attempts"]))
                    }
                    Lang::Fr => format!(
                        "{} sur {name} {} de {ip}.",
                        count(lang, n, ["tentative de connexion échouée", "", "tentatives de connexion échouées"]),
                        if n > 1 { "provenaient" } else { "provenait" }
                    ),
                    Lang::De => format!(
                        "Von {ip} {} {} für {name}.",
                        if n == 1 { "kam" } else { "kamen" },
                        count(lang, n, ["fehlgeschlagener Anmeldeversuch", "", "fehlgeschlagene Anmeldeversuche"])
                    ),
                    Lang::Ru => format!(
                        "С адреса {ip}: {} входа в учётную запись {name}.",
                        count(lang, n, ["неудачная попытка", "неудачные попытки", "неудачных попыток"])
                    ),
                    Lang::Uk => format!(
                        "З адреси {ip}: {} входу до облікового запису {name}.",
                        count(lang, n, ["невдала спроба", "невдалі спроби", "невдалих спроб"])
                    ),
                    Lang::Pl => format!(
                        "Z adresu {ip}: {} logowania na konto {name}.",
                        count(lang, n, ["nieudana próba", "nieudane próby", "nieudanych prób"])
                    ),
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
        UserNotice::Compromise { ip, place, at } => {
            let (from, at) = (where_from(lang, *ip, place), fmt_ts(*at));
            match lang {
                Lang::En => format!(
                    "Someone logged in to your account from {from} at {at} UTC, right after failed or suspicious login \
                     attempts from the same address. If this was not you, change your password immediately and contact \
                     the administrator."
                ),
                Lang::Fr => format!(
                    "Quelqu'un s'est connecté à votre compte depuis {from} le {at} UTC, juste après des tentatives de \
                     connexion échouées ou suspectes depuis la même adresse. Si ce n'était pas vous, changez immédiatement \
                     votre mot de passe et contactez l'administrateur."
                ),
                Lang::De => format!(
                    "Jemand hat sich am {at} UTC von {from} aus bei Ihrem Konto angemeldet, direkt nach fehlgeschlagenen \
                     oder verdächtigen Anmeldeversuchen von derselben Adresse. Falls Sie das nicht waren, ändern Sie sofort \
                     Ihr Passwort und wenden Sie sich an den Administrator."
                ),
                Lang::Ru => format!(
                    "Кто-то вошёл в вашу учётную запись с адреса {from} в {at} UTC сразу после неудачных или подозрительных \
                     попыток входа с того же адреса. Если это были не вы, немедленно смените пароль и свяжитесь с \
                     администратором."
                ),
                Lang::Uk => format!(
                    "Хтось увійшов до вашого облікового запису з адреси {from} о {at} UTC одразу після невдалих або \
                     підозрілих спроб входу з тієї ж адреси. Якщо це були не ви, негайно змініть пароль і зверніться до \
                     адміністратора."
                ),
                Lang::Pl => format!(
                    "Ktoś zalogował się na Twoje konto z adresu {from} o {at} UTC, zaraz po nieudanych lub podejrzanych \
                     próbach logowania z tego samego adresu. Jeśli to nie Ty, natychmiast zmień hasło i skontaktuj się \
                     z administratorem."
                ),
            }
        }
        UserNotice::NewLogin { ip, place, network, at } => {
            let at = fmt_ts(*at);
            let from = match (place, lang) {
                (Some(p), Lang::En) => format!("{p}, address {ip}"),
                (Some(p), Lang::Fr) => format!("{p}, adresse {ip}"),
                (Some(p), Lang::De) => format!("{p}, Adresse {ip}"),
                (Some(p), Lang::Ru) => format!("{p}, адрес {ip}"),
                (Some(p), Lang::Uk) => format!("{p}, адреса {ip}"),
                (Some(p), Lang::Pl) => format!("{p}, adres {ip}"),
                (None, Lang::En) => format!("{ip} (network {network})"),
                (None, Lang::Fr) => format!("{ip} (réseau {network})"),
                (None, Lang::De) => format!("{ip} (Netz {network})"),
                (None, Lang::Ru) => format!("адрес {ip} (сеть {network})"),
                (None, Lang::Uk) => format!("адреса {ip} (мережа {network})"),
                (None, Lang::Pl) => format!("adres {ip} (sieć {network})"),
            };
            match lang {
                Lang::En => format!("New login to your account from {from} at {at} UTC. If this was you, no action is needed."),
                Lang::Fr => {
                    format!("Nouvelle connexion à votre compte depuis {from} le {at} UTC. Si c'était vous, aucune action n'est nécessaire.")
                }
                Lang::De => format!("Neue Anmeldung bei Ihrem Konto von {from} am {at} UTC. Falls Sie das waren, ist nichts zu tun."),
                Lang::Ru => format!("Новый вход в вашу учётную запись: {from}, {at} UTC. Если это были вы, ничего делать не нужно."),
                Lang::Uk => {
                    format!("Новий вхід до вашого облікового запису: {from}, {at} UTC. Якщо це були ви, нічого робити не потрібно.")
                }
                Lang::Pl => format!("Nowe logowanie na Twoje konto: {from}, {at} UTC. Jeśli to Ty, nic nie trzeba robić."),
            }
        }
    }
}

/// Short name of a user-facing topic.
pub fn topic(t: Topic, lang: Lang) -> &'static str {
    match (t, lang) {
        (Topic::AccountAttack, Lang::En) => "account under attack",
        (Topic::AccountAttack, Lang::Fr) => "compte attaqué",
        (Topic::AccountAttack, Lang::De) => "Konto wird angegriffen",
        (Topic::AccountAttack, Lang::Ru) => "атака на учётную запись",
        (Topic::AccountAttack, Lang::Uk) => "атака на обліковий запис",
        (Topic::AccountAttack, Lang::Pl) => "atak na konto",
        (Topic::BruteForce, Lang::En) => "password guessing blocked",
        (Topic::BruteForce, Lang::Fr) => "tentatives sur le mot de passe bloquées",
        (Topic::BruteForce, Lang::De) => "Passwort-Rateversuche blockiert",
        (Topic::BruteForce, Lang::Ru) => "подбор пароля заблокирован",
        (Topic::BruteForce, Lang::Uk) => "підбір пароля заблоковано",
        (Topic::BruteForce, Lang::Pl) => "zablokowano zgadywanie hasła",
        (Topic::Compromise, Lang::En) => "suspicious login",
        (Topic::Compromise, Lang::Fr) => "connexion suspecte",
        (Topic::Compromise, Lang::De) => "verdächtige Anmeldung",
        (Topic::Compromise, Lang::Ru) => "подозрительный вход",
        (Topic::Compromise, Lang::Uk) => "підозрілий вхід",
        (Topic::Compromise, Lang::Pl) => "podejrzane logowanie",
        (Topic::NewNetwork, Lang::En) => "new login location",
        (Topic::NewNetwork, Lang::Fr) => "connexion depuis un nouvel endroit",
        (Topic::NewNetwork, Lang::De) => "Anmeldung von einem neuen Ort",
        (Topic::NewNetwork, Lang::Ru) => "вход из нового места",
        (Topic::NewNetwork, Lang::Uk) => "вхід з нового місця",
        (Topic::NewNetwork, Lang::Pl) => "logowanie z nowego miejsca",
        (t, _) => crate::notify::topic_name(t),
    }
}

pub fn subject(t: Topic, lang: Lang) -> String {
    let prefix = match lang {
        Lang::En => "Security notice: ",
        Lang::Fr => "Avis de sécurité : ",
        Lang::De => "Sicherheitshinweis: ",
        Lang::Ru => "Уведомление о безопасности: ",
        Lang::Uk => "Повідомлення про безпеку: ",
        Lang::Pl => "Powiadomienie o bezpieczeństwie: ",
    };
    format!("⚠️ {prefix}{}", topic(t, lang))
}

/// Fixed sentences around a notice.
pub struct Phrases {
    pub header: &'static str,
    pub blocks: &'static str,
    /// A sentence with `{dur}` where `duration()` goes (word order differs by language).
    pub blocked_for: &'static str,
    pub advice: &'static str,
    pub footer: &'static str,
    pub test: &'static str,
}

pub fn phrases(lang: Lang) -> Phrases {
    match lang {
        Lang::En => Phrases {
            header: "Security notice for",
            blocks: "The server blocks the attacking addresses automatically.",
            blocked_for: "This address is blocked for {dur}.",
            advice: "None of these attempts succeeded. If your password is short, or you use it anywhere else, change it now \
                     (in your app: account settings → change password).",
            footer: "This is an automatic message from the server.",
            test: "This is a test message from logguard. If you can read it, security notifications work.",
        },
        Lang::Fr => Phrases {
            header: "Avis de sécurité pour",
            blocks: "Le serveur bloque automatiquement les adresses à l'origine de l'attaque.",
            blocked_for: "Cette adresse est bloquée pendant {dur}.",
            advice: "Aucune de ces tentatives n'a abouti. Si votre mot de passe est court, ou si vous l'utilisez ailleurs, \
                     changez-le maintenant (dans votre application : paramètres du compte → changer le mot de passe).",
            footer: "Ceci est un message automatique du serveur.",
            test: "Ceci est un message de test de logguard. Si vous pouvez le lire, les notifications de sécurité fonctionnent.",
        },
        Lang::De => Phrases {
            header: "Sicherheitshinweis für",
            blocks: "Der Server sperrt die angreifenden Adressen automatisch.",
            blocked_for: "Diese Adresse ist für {dur} gesperrt.",
            advice: "Keiner dieser Versuche war erfolgreich. Wenn Ihr Passwort kurz ist oder Sie es auch anderswo verwenden, \
                     ändern Sie es jetzt (in Ihrer App: Kontoeinstellungen → Passwort ändern).",
            footer: "Dies ist eine automatische Nachricht des Servers.",
            test: "Dies ist eine Testnachricht von logguard. Wenn Sie sie lesen können, funktionieren die Sicherheitsbenachrichtigungen.",
        },
        Lang::Ru => Phrases {
            header: "Уведомление о безопасности для",
            blocks: "Сервер автоматически блокирует атакующие адреса.",
            blocked_for: "Этот адрес заблокирован на {dur}.",
            advice: "Ни одна из этих попыток не удалась. Если ваш пароль короткий или вы используете его где-то ещё, \
                     смените его сейчас (в приложении: настройки учётной записи → сменить пароль).",
            footer: "Это автоматическое сообщение от сервера.",
            test: "Это тестовое сообщение от logguard. Если вы его видите, уведомления о безопасности работают.",
        },
        Lang::Uk => Phrases {
            header: "Повідомлення про безпеку для",
            blocks: "Сервер автоматично блокує адреси, з яких іде атака.",
            blocked_for: "Цю адресу заблоковано на {dur}.",
            advice: "Жодна з цих спроб не вдалася. Якщо ваш пароль короткий або ви використовуєте його деінде, \
                     змініть його зараз (у застосунку: налаштування облікового запису → змінити пароль).",
            footer: "Це автоматичне повідомлення від сервера.",
            test: "Це тестове повідомлення від logguard. Якщо ви його бачите, сповіщення про безпеку працюють.",
        },
        Lang::Pl => Phrases {
            header: "Powiadomienie o bezpieczeństwie dla",
            blocks: "Serwer automatycznie blokuje atakujące adresy.",
            blocked_for: "Ten adres jest zablokowany na {dur}.",
            advice: "Żadna z tych prób się nie powiodła. Jeśli Twoje hasło jest krótkie lub używasz go gdzie indziej, \
                     zmień je teraz (w aplikacji: ustawienia konta → zmień hasło).",
            footer: "To jest automatyczna wiadomość z serwera.",
            test: "To jest wiadomość testowa od logguard. Jeśli ją widzisz, powiadomienia o bezpieczeństwie działają.",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plurals_and_durations() {
        let h = 3600 * SEC;
        assert_eq!(duration(Lang::En, h), "1 hour");
        assert_eq!(duration(Lang::En, 6 * h), "6 hours");
        assert_eq!(duration(Lang::Fr, 7 * 24 * h), "7 jours");
        assert_eq!(duration(Lang::De, h), "1 Stunde");
        assert_eq!(duration(Lang::De, 30 * 24 * h), "30 Tage");
        assert_eq!(duration(Lang::Ru, h), "1 час");
        assert_eq!(duration(Lang::Ru, 6 * h), "6 часов");
        assert_eq!(duration(Lang::Ru, 24 * h), "1 день");
        assert_eq!(duration(Lang::Ru, 3 * 24 * h), "3 дня");
        assert_eq!(duration(Lang::Ru, 30 * 24 * h), "30 дней");
        assert_eq!(duration(Lang::Uk, 21 * h), "21 годину");
        assert_eq!(duration(Lang::Uk, 2 * h), "2 години");
        assert_eq!(duration(Lang::Uk, 11 * 24 * h), "11 днів");
        assert_eq!(duration(Lang::Uk, 30 * 60 * SEC), "30 хвилин");
        assert_eq!(duration(Lang::En, 30 * h), "1 day 6 hours");
        assert_eq!(slavic(11), 2);
        assert_eq!(slavic(21), 0);
        assert_eq!(slavic(112), 2);
        assert_eq!(slavic(102), 1);
        assert_eq!(duration(Lang::Pl, h), "1 godzinę");
        assert_eq!(duration(Lang::Pl, 2 * h), "2 godziny");
        assert_eq!(duration(Lang::Pl, 6 * h), "6 godzin");
        assert_eq!(duration(Lang::Pl, 21 * h), "21 godzin", "21 is 'many' in Polish");
        assert_eq!(duration(Lang::Pl, 22 * h), "22 godziny");
        assert_eq!(duration(Lang::Pl, 24 * h), "1 dzień");
        assert_eq!(duration(Lang::Pl, 7 * 24 * h), "7 dni");
        assert_eq!(duration(Lang::Pl, 30 * 60 * SEC), "30 minut");
        assert_eq!(duration(Lang::Pl, 60 * SEC), "1 minutę");
        assert_eq!((polish(1), polish(4), polish(5), polish(12), polish(14), polish(21), polish(24), polish(0)), (0, 1, 2, 2, 2, 2, 1, 2));
    }

    #[test]
    fn notices_in_every_language() {
        let attack = UserNotice::AccountAttack { failures: 21, addresses: 5 };
        assert!(note(&attack, Lang::Ru, None).contains("около 21 неудачной попытки входа с 5 разных адресов"));
        assert!(note(&attack, Lang::Uk, None).contains("близько 21 невдалої спроби входу з 5 різних адрес"));
        assert!(note(&attack, Lang::Fr, None).starts_with("Votre compte"));
        let bf = UserNotice::BruteForce {
            ip: "11.10.2.3".parse().unwrap(),
            attempts: [("ejabberd:alice@x.org".to_string(), 1), ("ejabberd:bob@x.org".to_string(), 3)].into_iter().collect(),
        };
        assert_eq!(
            note(&bf, Lang::Ru, Some("ejabberd:bob@x.org")),
            "С адреса 11.10.2.3: 3 неудачные попытки входа в учётную запись bob@x.org."
        );
        assert_eq!(
            note(&bf, Lang::Fr, Some("ejabberd:alice@x.org")),
            "1 tentative de connexion échouée sur alice@x.org provenait de 11.10.2.3."
        );
        assert!(!note(&bf, Lang::En, Some("ejabberd:bob@x.org")).contains("alice"), "other users' accounts are never revealed");
        assert_eq!(note(&bf, Lang::En, None).matches("came from").count(), 2, "the admin/log version lists all");
        assert_eq!(subject(Topic::Compromise, Lang::Uk), "⚠️ Повідомлення про безпеку: підозрілий вхід");
        assert_eq!(note(&bf, Lang::De, Some("ejabberd:bob@x.org")), "Von 11.10.2.3 kamen 3 fehlgeschlagene Anmeldeversuche für bob@x.org.");
        assert_eq!(
            note(&bf, Lang::De, Some("ejabberd:alice@x.org")),
            "Von 11.10.2.3 kam 1 fehlgeschlagener Anmeldeversuch für alice@x.org."
        );
        assert_eq!(subject(Topic::AccountAttack, Lang::De), "⚠️ Sicherheitshinweis: Konto wird angegriffen");
        assert_eq!(note(&bf, Lang::Pl, Some("ejabberd:bob@x.org")), "Z adresu 11.10.2.3: 3 nieudane próby logowania na konto bob@x.org.");
        assert_eq!(
            note(&bf, Lang::Pl, Some("ejabberd:alice@x.org")),
            "Z adresu 11.10.2.3: 1 nieudana próba logowania na konto alice@x.org."
        );
        assert!(note(&attack, Lang::Pl, None).contains("około 21 nieudanych prób logowania z 5 różnych adresów"));
        let one = UserNotice::AccountAttack { failures: 1, addresses: 1 };
        assert!(note(&one, Lang::Pl, None).contains("około 1 nieudanej próby logowania z 1 adresu"));
        assert_eq!(subject(Topic::Compromise, Lang::Pl), "⚠️ Powiadomienie o bezpieczeństwie: podejrzane logowanie");
        for lang in [Lang::En, Lang::Fr, Lang::De, Lang::Ru, Lang::Uk, Lang::Pl] {
            assert!(phrases(lang).blocked_for.contains("{dur}"));
            let p = phrases(lang);
            assert!(!p.header.is_empty() && !p.footer.is_empty() && !p.test.is_empty());
            let nl = UserNotice::NewLogin { ip: "1.0.0.7".parse().unwrap(), place: None, network: "1.0.0.0/16".parse().unwrap(), at: 0 };
            assert!(note(&nl, lang, None).contains("1.0.0.0/16"));
        }
    }

    #[test]
    fn language_names() {
        #[derive(Deserialize)]
        struct T {
            l: Vec<Lang>,
        }
        let t: T = toml::from_str(
            r#"l = ["en", "english", "fr", "français", "de", "deutsch", "ru", "russian", "uk", "ukrainian", "pl", "polski"]"#,
        )
        .unwrap();
        assert_eq!(
            t.l,
            vec![Lang::En, Lang::En, Lang::Fr, Lang::Fr, Lang::De, Lang::De, Lang::Ru, Lang::Ru, Lang::Uk, Lang::Uk, Lang::Pl, Lang::Pl]
        );
        assert!(toml::from_str::<T>(r#"l = ["es"]"#).is_err());
    }
}
