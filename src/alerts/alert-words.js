/**
 * The words of the security alerts (spec 25.7): the subject and the text of
 * every email, in English and in Thai, and the facts a phone is sent.
 *
 * An email is plain text: no picture, no formatting and no link. One
 * paragraph is one line, and an empty line stands between two paragraphs.
 * A phone is sent facts, not sentences: its sentence is made on the phone,
 * in the phone's own language, by the wallet's public/alerts-worker.js.
 *
 * The Thai is written in the words of the wallet's Thai dictionary
 * (web_app/src/app/i18n/th.ts). What an email quotes from the wallet's
 * screens stands in `buttons`, and has to stay what the wallet shows.
 */

/**
 * How many minutes after a transfer was sent the wallet lets a person
 * cancel it. A copy of LOCK_OFFSET_MINUTES in
 * anossoftware/network/testnet.env: when that changes, this changes.
 */
const CANCEL_AFTER_MINUTES = 10;

const WORDS = {
  en: {
    /** The tag a day is written with. */
    tag: 'en-GB',
    /**
     * What an email quotes from the wallet, as en.ts has it: cancelTransfer,
     * recoverAccount, accountAlerts.title, accountAlerts.keep, nav.account.
     */
    buttons: { cancelTransfer: 'Cancel transfer', recoverAccount: 'Recover account', alerts: 'Security alerts', keep: 'Keep', account: 'Account' },
    /** The kinds of account, the wallet's words for them in lower case; any other kind reads as `account`. */
    kinds: { spending: 'spending account', guarded: 'guarded account', vault: 'vault account', assisted: 'assisted account' },
    account: 'account',
    /** The device words; anything else reads as `other`. */
    labels: { iphone: 'an iPhone', ipad: 'an iPad', android: 'an Android phone', computer: 'a computer', other: 'a device' },
    /** An email whose row is gone when the message is sent. */
    goneEmail: 'an address that is no longer on the list',
    inTime: (hours) => (hours >= 48 ? `in ${Math.round(hours / 24)} days` : hours >= 2 ? `in ${hours} hours` : 'within the hour'),
    moment: (day, time) => `${day} at ${time} UTC`,
    noLink: 'We never put a link in an email. Open the wallet the way you always do.',
    noReplies: 'This email was sent by the anoPod wallet. Nobody reads replies to it.',

    transferWaiting: ({ anos, account, start, when }, b) => ({
      subject: `A transfer is waiting to leave your ${account}`,
      paragraphs: [
        `A transfer of ${anos} anos is waiting to leave your ${account}. ${when === null ? 'It is waiting on the validators.' : `It will be written ${when.inTime}, on ${when.moment}.`}`,
        'If you sent it, do nothing.',
        `If you did not send it, cancel it now. Open the wallet, open that account (its id starts with ${start}), and tap "${b.cancelTransfer}". The wallet lets you cancel from ${CANCEL_AFTER_MINUTES} minutes after the transfer was sent until it is written.`,
      ],
    }),
    assistedTransferWaiting: ({ anos, account, start }, b) => ({
      subject: `A transfer is waiting to leave your ${account}`,
      paragraphs: [
        `A transfer of ${anos} anos is waiting to leave your ${account}. It is written once two attestors have checked it.`,
        'If you sent it, do nothing. An attestor will open a case and meet you on a video call.',
        `If you did not send it, cancel it now. Open the wallet, open that account (its id starts with ${start}), tap the waiting transfer, and tap "${b.cancelTransfer}". The wallet lets you cancel from ${CANCEL_AFTER_MINUTES} minutes after the transfer was sent until it is written.`,
      ],
    }),
    recoveryMoveWaiting: ({ anos, account, start, when }, b) => ({
      subject: `A recovery is moving anos out of your ${account}`,
      paragraphs: [
        `A recovery of your anoPod is moving ${anos} anos out of your ${account} (its id starts with ${start}) to a new account. ${when === null ? 'The move is written once two attestors have signed it off.' : `The move will be written ${when.inTime}, on ${when.moment}, once two attestors have signed it off.`}`,
        'If you are recovering your anoPod, do nothing.',
        `If you are not, someone else has taken your anoPod over. Open the wallet's first page and tap "${b.recoverAccount}". A moderator will then meet you on a video call.`,
      ],
    }),
    recoveryCaseOpened: (facts, b) => ({
      subject: 'A recovery was started for your anoPod',
      paragraphs: [
        'Someone has started a recovery of your anoPod. A recovery is how a person who lost their passkey gets back in.',
        'If you started it, do nothing.',
        `If you did not: a moderator checks every recovery on a video call before anything is released. If your passkey ever stops working, open the wallet's first page and tap "${b.recoverAccount}".`,
      ],
    }),
    // The seven emails about the list. "30 days" is ALERT_REMOVE_MINUTES at its default, a month.
    didThis: 'If you did this, do nothing.',
    seeList: (b) => `If you did not, open the wallet, tap ${b.account}, then "${b.alerts}", to see the list.`,
    someoneElse: (b) => `If you did not, someone else is in your wallet. Your own emails and phones stay on the list: one that is taken off still gets every alert for 30 days. Open the wallet, tap ${b.account}, then "${b.alerts}", to see the list.`,
    emailAdded: ({ email }) => ({
      subject: 'An email was added to your security alerts',
      first: `The email address ${email} was added to the security alerts of your anoPod. It now gets every alert.`,
      otherwise: 'someoneElse',
    }),
    emailRemoving: ({ email, day }, b) => ({
      subject: 'An email will come off your security alerts',
      first: `The email address ${email} is set to come off the security alerts of your anoPod on ${day}. Until then it still gets every alert.`,
      otherwise: `If you did not, open the wallet, tap ${b.account}, then "${b.alerts}", and tap "${b.keep}" beside that address.`,
    }),
    emailKept: ({ email }) => ({
      subject: 'An email stays on your security alerts',
      first: `The email address ${email} is no longer set to come off the security alerts of your anoPod. It stays on the list.`,
      otherwise: 'seeList',
    }),
    phoneAdded: ({ label }) => ({
      subject: 'A phone was added to your security alerts',
      first: `A phone was added to the security alerts of your anoPod: ${label}. It now gets every alert.`,
      otherwise: 'someoneElse',
    }),
    phoneRemoving: ({ label, day }, b) => ({
      subject: 'A phone will come off your security alerts',
      first: `A phone is set to come off the security alerts of your anoPod on ${day}: ${label}. Until then it still gets every alert.`,
      otherwise: `If you did not, open the wallet, tap ${b.account}, then "${b.alerts}", and tap "${b.keep}" beside that phone.`,
    }),
    phoneKept: ({ label }) => ({
      subject: 'A phone stays on your security alerts',
      first: `A phone is no longer set to come off the security alerts of your anoPod: ${label}. It stays on the list.`,
      otherwise: 'seeList',
    }),
    // This one has no "If you did this" line.
    phoneUnreachable: ({ label }, b) => ({
      subject: 'A phone no longer gets your security alerts',
      paragraphs: [
        `A phone on the security alerts of your anoPod can no longer be reached: ${label}. It was taken off the list. This happens when the wallet is removed from the phone's Home Screen, or when its notifications are switched off in the phone's settings.`,
        `If you want alerts on that phone again, open the wallet on it, tap ${b.account}, then "${b.alerts}", and turn them on. Your emails still get every alert.`,
      ],
    }),
    // The code. It ends with the one line about replies.
    emailCode: ({ code }) => ({
      subject: 'Your code for security alerts',
      paragraphs: [
        `Your code is ${code}.`,
        'Type it into the wallet to confirm this email address for security alerts. The code is good for 10 minutes.',
        'If you did not ask for it, do nothing. Without the code this address gets no alerts.',
      ],
    }),
  },

  th: {
    /** The wallet's tag for Thai: the Thai words with the years of the Gregorian calendar. */
    tag: 'th-TH-u-ca-gregory',
    /**
     * What an email quotes from the wallet, as th.ts has it: cancelTransfer,
     * recoverAccount, accountAlerts.title, accountAlerts.keep, nav.account.
     */
    buttons: { cancelTransfer: 'ยกเลิกการโอน', recoverAccount: 'กู้คืนบัญชี', alerts: 'การแจ้งเตือนความปลอดภัย', keep: 'เก็บไว้', account: 'บัญชี' },
    /** The kinds of account, the phrases of accountKinds in th.ts; any other kind reads as `account`. */
    kinds: { spending: 'บัญชีใช้จ่าย', guarded: 'บัญชีหน่วงเวลา', vault: 'บัญชีนิรภัย', assisted: 'บัญชีมีผู้ยืนยัน' },
    account: 'บัญชี',
    labels: { iphone: 'iPhone', ipad: 'iPad', android: 'โทรศัพท์ Android', computer: 'คอมพิวเตอร์', other: 'อุปกรณ์เครื่องหนึ่ง' },
    goneEmail: 'ที่อยู่ที่ไม่อยู่ในรายการแล้ว',
    inTime: (hours) => (hours >= 48 ? `ในอีก ${Math.round(hours / 24)} วัน` : hours >= 2 ? `ในอีก ${hours} ชั่วโมง` : 'ภายในหนึ่งชั่วโมง'),
    moment: (day, time) => `${day} เวลา ${time} UTC`,
    noLink: 'เราไม่ใส่ลิงก์ในอีเมลเลย เปิดกระเป๋าเงินด้วยวิธีที่คุณเปิดเป็นประจำ',
    noReplies: 'อีเมลนี้ส่งโดยกระเป๋าเงิน anoPod ไม่มีใครอ่านข้อความตอบกลับอีเมลนี้',

    transferWaiting: ({ anos, account, start, when }, b) => ({
      subject: `มีการโอนกำลังรอออกจาก${account}ของคุณ`,
      paragraphs: [
        `การโอน ${anos} anos กำลังรอออกจาก${account}ของคุณ ${when === null ? 'การโอนกำลังรออยู่บนผู้ตรวจสอบ' : `การโอนจะถูกเขียน${when.inTime} ในวันที่ ${when.moment}`}`,
        'หากคุณเป็นผู้ส่ง ไม่ต้องทำอะไร',
        `หากคุณไม่ได้ส่ง ให้ยกเลิกทันที เปิดกระเป๋าเงิน เปิดบัญชีนั้น (รหัสบัญชีขึ้นต้นด้วย ${start}) แล้วแตะ "${b.cancelTransfer}" กระเป๋าเงินให้คุณยกเลิกได้ตั้งแต่ ${CANCEL_AFTER_MINUTES} นาทีหลังจากส่งการโอน จนกว่าการโอนจะถูกเขียน`,
      ],
    }),
    assistedTransferWaiting: ({ anos, account, start }, b) => ({
      subject: `มีการโอนกำลังรอออกจาก${account}ของคุณ`,
      paragraphs: [
        `การโอน ${anos} anos กำลังรอออกจาก${account}ของคุณ การโอนจะถูกเขียนเมื่อผู้ยืนยันสองคนตรวจสอบแล้ว`,
        'หากคุณเป็นผู้ส่ง ไม่ต้องทำอะไร ผู้ยืนยันจะเปิดเคสและพบคุณทางวิดีโอคอล',
        `หากคุณไม่ได้ส่ง ให้ยกเลิกทันที เปิดกระเป๋าเงิน เปิดบัญชีนั้น (รหัสบัญชีขึ้นต้นด้วย ${start}) แตะการโอนที่กำลังรอ แล้วแตะ "${b.cancelTransfer}" กระเป๋าเงินให้คุณยกเลิกได้ตั้งแต่ ${CANCEL_AFTER_MINUTES} นาทีหลังจากส่งการโอน จนกว่าการโอนจะถูกเขียน`,
      ],
    }),
    recoveryMoveWaiting: ({ anos, account, start, when }, b) => ({
      subject: `การกู้คืนกำลังย้าย anos ออกจาก${account}ของคุณ`,
      paragraphs: [
        `การกู้คืน anoPod ของคุณกำลังย้าย ${anos} anos ออกจาก${account}ของคุณ (รหัสบัญชีขึ้นต้นด้วย ${start}) ไปยังบัญชีใหม่ ${when === null ? 'การย้ายจะถูกเขียนเมื่อผู้ยืนยันสองคนลงนามแล้ว' : `การย้ายจะถูกเขียน${when.inTime} ในวันที่ ${when.moment} เมื่อผู้ยืนยันสองคนลงนามแล้ว`}`,
        'หากคุณกำลังกู้คืน anoPod ของคุณ ไม่ต้องทำอะไร',
        `หากไม่ใช่คุณ แสดงว่ามีคนอื่นยึด anoPod ของคุณไปแล้ว เปิดหน้าแรกของกระเป๋าเงินแล้วแตะ "${b.recoverAccount}" จากนั้นผู้ดูแลจะพบคุณทางวิดีโอคอล`,
      ],
    }),
    recoveryCaseOpened: (facts, b) => ({
      subject: 'มีการเริ่มการกู้คืน anoPod ของคุณ',
      paragraphs: [
        'มีคนเริ่มการกู้คืน anoPod ของคุณ การกู้คืนคือวิธีที่ผู้ที่ทำพาสคีย์หายกลับเข้ามาได้',
        'หากคุณเป็นผู้เริ่ม ไม่ต้องทำอะไร',
        `หากคุณไม่ได้เริ่ม: ผู้ดูแลจะตรวจสอบการกู้คืนทุกครั้งทางวิดีโอคอลก่อนที่จะปล่อยสิ่งใด หากวันหนึ่งพาสคีย์ของคุณใช้ไม่ได้ ให้เปิดหน้าแรกของกระเป๋าเงินแล้วแตะ "${b.recoverAccount}"`,
      ],
    }),
    // The seven emails about the list. "30 วัน" is ALERT_REMOVE_MINUTES at its default, a month.
    didThis: 'หากคุณเป็นผู้ทำ ไม่ต้องทำอะไร',
    seeList: (b) => `หากคุณไม่ได้ทำ ให้เปิดกระเป๋าเงิน แตะ "${b.account}" แล้วแตะ "${b.alerts}" เพื่อดูรายการ`,
    someoneElse: (b) => `หากคุณไม่ได้ทำ แสดงว่ามีคนอื่นอยู่ในกระเป๋าเงินของคุณ อีเมลและโทรศัพท์ของคุณเองยังอยู่ในรายการ: อีเมลหรือโทรศัพท์ที่ถูกนำออกจะยังได้รับการแจ้งเตือนทุกครั้งต่อไปอีก 30 วัน เปิดกระเป๋าเงิน แตะ "${b.account}" แล้วแตะ "${b.alerts}" เพื่อดูรายการ`,
    emailAdded: ({ email }) => ({
      subject: 'มีการเพิ่มอีเมลในการแจ้งเตือนความปลอดภัยของคุณ',
      first: `ที่อยู่อีเมล ${email} ถูกเพิ่มในการแจ้งเตือนความปลอดภัยของ anoPod ของคุณ ตอนนี้ที่อยู่นี้จะได้รับการแจ้งเตือนทุกครั้ง`,
      otherwise: 'someoneElse',
    }),
    emailRemoving: ({ email, day }, b) => ({
      subject: 'อีเมลหนึ่งรายการจะออกจากการแจ้งเตือนความปลอดภัยของคุณ',
      first: `ที่อยู่อีเมล ${email} ถูกตั้งให้ออกจากการแจ้งเตือนความปลอดภัยของ anoPod ของคุณในวันที่ ${day} จนถึงวันนั้นที่อยู่นี้จะยังได้รับการแจ้งเตือนทุกครั้ง`,
      otherwise: `หากคุณไม่ได้ทำ ให้เปิดกระเป๋าเงิน แตะ "${b.account}" แล้วแตะ "${b.alerts}" จากนั้นแตะ "${b.keep}" ข้างที่อยู่นั้น`,
    }),
    emailKept: ({ email }) => ({
      subject: 'อีเมลหนึ่งรายการยังอยู่ในการแจ้งเตือนความปลอดภัยของคุณ',
      first: `ที่อยู่อีเมล ${email} ไม่ได้ถูกตั้งให้ออกจากการแจ้งเตือนความปลอดภัยของ anoPod ของคุณอีกต่อไป ที่อยู่นี้ยังอยู่ในรายการ`,
      otherwise: 'seeList',
    }),
    phoneAdded: ({ label }) => ({
      subject: 'มีการเพิ่มโทรศัพท์ในการแจ้งเตือนความปลอดภัยของคุณ',
      first: `มีการเพิ่มโทรศัพท์ในการแจ้งเตือนความปลอดภัยของ anoPod ของคุณ: ${label} ตอนนี้โทรศัพท์เครื่องนี้จะได้รับการแจ้งเตือนทุกครั้ง`,
      otherwise: 'someoneElse',
    }),
    phoneRemoving: ({ label, day }, b) => ({
      subject: 'โทรศัพท์เครื่องหนึ่งจะออกจากการแจ้งเตือนความปลอดภัยของคุณ',
      first: `โทรศัพท์เครื่องหนึ่งถูกตั้งให้ออกจากการแจ้งเตือนความปลอดภัยของ anoPod ของคุณในวันที่ ${day}: ${label} จนถึงวันนั้นโทรศัพท์เครื่องนี้จะยังได้รับการแจ้งเตือนทุกครั้ง`,
      otherwise: `หากคุณไม่ได้ทำ ให้เปิดกระเป๋าเงิน แตะ "${b.account}" แล้วแตะ "${b.alerts}" จากนั้นแตะ "${b.keep}" ข้างโทรศัพท์เครื่องนั้น`,
    }),
    phoneKept: ({ label }) => ({
      subject: 'โทรศัพท์เครื่องหนึ่งยังอยู่ในการแจ้งเตือนความปลอดภัยของคุณ',
      first: `โทรศัพท์เครื่องหนึ่งไม่ได้ถูกตั้งให้ออกจากการแจ้งเตือนความปลอดภัยของ anoPod ของคุณอีกต่อไป: ${label} โทรศัพท์เครื่องนี้ยังอยู่ในรายการ`,
      otherwise: 'seeList',
    }),
    phoneUnreachable: ({ label }, b) => ({
      subject: 'โทรศัพท์เครื่องหนึ่งไม่ได้รับการแจ้งเตือนความปลอดภัยของคุณอีกต่อไป',
      paragraphs: [
        `ติดต่อโทรศัพท์เครื่องหนึ่งในการแจ้งเตือนความปลอดภัยของ anoPod ของคุณไม่ได้อีกต่อไป: ${label} โทรศัพท์เครื่องนี้ถูกนำออกจากรายการแล้ว กรณีนี้เกิดขึ้นเมื่อกระเป๋าเงินถูกนำออกจากหน้าจอโฮมของโทรศัพท์ หรือเมื่อการแจ้งเตือนของกระเป๋าเงินถูกปิดในการตั้งค่าของโทรศัพท์`,
        `หากคุณต้องการรับการแจ้งเตือนบนโทรศัพท์เครื่องนั้นอีกครั้ง ให้เปิดกระเป๋าเงินบนเครื่องนั้น แตะ "${b.account}" แล้วแตะ "${b.alerts}" จากนั้นเปิดการแจ้งเตือน อีเมลของคุณยังได้รับการแจ้งเตือนทุกครั้ง`,
      ],
    }),
    emailCode: ({ code }) => ({
      subject: 'รหัสของคุณสำหรับการแจ้งเตือนความปลอดภัย',
      paragraphs: [
        `รหัสของคุณคือ ${code}`,
        'พิมพ์รหัสนี้ในกระเป๋าเงินเพื่อยืนยันที่อยู่อีเมลนี้สำหรับการแจ้งเตือนความปลอดภัย รหัสนี้ใช้ได้ 10 นาที',
        'หากคุณไม่ได้ขอรหัสนี้ ไม่ต้องทำอะไร หากไม่มีรหัส ที่อยู่นี้จะไม่ได้รับการแจ้งเตือน',
      ],
    }),
  },
};

/** The kinds that tell of a change of an email on the list, and of a phone on it. */
const EMAIL_KINDS = ['emailAdded', 'emailRemoving', 'emailKept'];
const PHONE_KINDS = ['phoneAdded', 'phoneRemoving', 'phoneKept', 'phoneUnreachable'];
const REMOVING_KINDS = ['emailRemoving', 'phoneRemoving'];
const TRANSFER_KINDS = ['transferWaiting', 'recoveryMoveWaiting'];

/**
 * Millionths of an anos, a decimal string, as anos with commas in the whole
 * part and the fraction's zeros dropped: "5000000000" is "5,000", "1500000"
 * is "1.5". On the digits, with BigInt, never through a float.
 */
function anosOf(millionths) {
  if (typeof millionths !== 'string' || !/^[0-9]+$/.test(millionths)) throw new TypeError('an amount must be a decimal string');
  const value = BigInt(millionths);
  const whole = (value / 1_000_000n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const fraction = (value % 1_000_000n).toString().padStart(6, '0').replace(/0+$/, '');
  return fraction === '' ? whole : `${whole}.${fraction}`;
}

/** The start of an account's id: its first 8 hex characters. */
function startOf(accountId) {
  if (typeof accountId !== 'string' || accountId.length < 8) throw new TypeError('an account id must be a hex string');
  return accountId.slice(0, 8);
}

/** A moment (an ISO string or a Date) as a Date. */
function dateOf(moment) {
  const date = new Date(moment);
  if (moment === null || moment === undefined || Number.isNaN(date.getTime())) throw new TypeError('a moment must be a date');
  return date;
}

/** A day in UTC, in the words of `tag`: "21 December 2026". */
function dayOf(date, tag) {
  return new Intl.DateTimeFormat(tag, { timeZone: 'UTC', day: 'numeric', month: 'long', year: 'numeric' }).format(date);
}

/** The hour and the minute in UTC, in the 24-hour form: "07:12". */
function timeOf(date) {
  return `${String(date.getUTCHours()).padStart(2, '0')}:${String(date.getUTCMinutes()).padStart(2, '0')}`;
}

/**
 * When a transfer is written, for a sentence: { inTime, moment }, "in 7
 * days" and "27 November 2026 at 07:12 UTC". The hours from now to the
 * moment are rounded up: 48 or more read as days (the hours divided by 24
 * and rounded), 2 to 47 as hours, fewer as "within the hour".
 */
function whenOf(moment, words) {
  const date = dateOf(moment);
  const hours = Math.ceil((date.getTime() - Date.now()) / 3_600_000);
  return { inTime: words.inTime(hours), moment: words.moment(dayOf(date, words.tag), timeOf(date)) };
}

/**
 * The email for one message: { subject, text }. `kind` is the message's
 * kind, `language` en or th (anything else reads as English), `facts` what
 * the sender read: amount, accountType, accountId and writesAt for the two
 * transfer kinds (writesAt null for a transfer that has no day); email for
 * the three email kinds (null when that row is gone); label for the four
 * phone kinds; removesAt for the two removing kinds; code for emailCode.
 *
 * Every kind has words for every case, so that no report of a validator
 * can make this throw. A transfer out of an assisted account reads as the
 * assisted email. A transfer out of any other account reads as the guarded
 * email with that account's kind in its words, and says "It is waiting on
 * the validators." when it has no day. A recovery's move reads with the
 * day when it has one and without it when it has none, whatever the
 * account's kind. It throws on a kind that has no email (phoneOn goes to a
 * phone alone) and on facts that are not what the kind carries; the sender
 * gives such a message up.
 */
export function emailOf(kind, language, facts) {
  const words = WORDS[language] ?? WORDS.en;
  let made;
  let ending = [words.noLink, words.noReplies];

  if (TRANSFER_KINDS.includes(kind)) {
    const told = {
      anos: anosOf(facts.amount),
      account: words.kinds[facts.accountType] ?? words.account,
      start: startOf(facts.accountId),
      when: facts.writesAt === null || facts.writesAt === undefined ? null : whenOf(facts.writesAt, words),
    };
    const maker = kind === 'recoveryMoveWaiting' ? words.recoveryMoveWaiting
      : facts.accountType === 'assisted' ? words.assistedTransferWaiting : words.transferWaiting;
    made = maker(told, words.buttons);
  } else if (kind === 'recoveryCaseOpened') {
    made = words.recoveryCaseOpened(facts, words.buttons);
  } else if (EMAIL_KINDS.includes(kind) || PHONE_KINDS.includes(kind)) {
    const told = {
      email: typeof facts.email === 'string' ? facts.email : words.goneEmail,
      label: words.labels[facts.label] ?? words.labels.other,
      day: REMOVING_KINDS.includes(kind) ? dayOf(dateOf(facts.removesAt), words.tag) : null,
    };
    made = words[kind](told, words.buttons);
    if (made.paragraphs === undefined) {
      const otherwise = made.otherwise === 'someoneElse' ? words.someoneElse(words.buttons)
        : made.otherwise === 'seeList' ? words.seeList(words.buttons) : made.otherwise;
      made = { subject: made.subject, paragraphs: [made.first, words.didThis, otherwise] };
    }
  } else if (kind === 'emailCode') {
    if (typeof facts.code !== 'string' || !/^[0-9]{6}$/.test(facts.code)) throw new TypeError('a code must be six digits');
    made = words.emailCode({ code: facts.code });
    ending = [words.noReplies];
  } else {
    throw new TypeError(`no email for the kind ${kind}`);
  }

  return { subject: made.subject, text: `${[...made.paragraphs, ...ending].join('\n\n')}\n` };
}

/**
 * What a phone is sent for one message: { kind } and, by kind, accountType
 * and amount (the two transfer kinds); or email (the three email kinds,
 * left out when that row is gone); or label (the four phone kinds); and
 * removesAt with the two removing kinds. Nothing else: no account id, no
 * pod id, and no day of a transfer, which the phone's sentence does not
 * say. recoveryCaseOpened and phoneOn carry the kind alone.
 */
export function phoneFactsOf(kind, facts) {
  const sent = { kind };
  if (TRANSFER_KINDS.includes(kind)) {
    sent.accountType = facts.accountType;
    sent.amount = facts.amount;
  } else if (EMAIL_KINDS.includes(kind)) {
    if (typeof facts.email === 'string') sent.email = facts.email;
  } else if (PHONE_KINDS.includes(kind)) {
    sent.label = facts.label;
  }
  if (REMOVING_KINDS.includes(kind)) sent.removesAt = facts.removesAt;
  return sent;
}
