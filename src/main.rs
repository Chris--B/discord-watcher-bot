use std::{
    cell::RefCell,
    env,
    error,
    fs,
    io::Read,
    path::PathBuf,
    str,
    sync::Mutex,
    time::{
        Instant,
        Duration,
    },
};

use failure::{
    bail,
    Error,
};

use serenity::{
    prelude::*,
    model::channel::Message,
    model::gateway::Ready,
};

use rand::{
    prelude::*,
    seq::SliceRandom,
};

use serde::{
    Serialize,
    Deserialize,
};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    /// Cooldown in seconds that the bot waits before responding again.
    /// Set to 0.0 to disable.
    pub cooldown:           f64,
    pub trigger_phrases:    Vec<String>,

    /// When composing a response, a single phrase from this list is selected at
    /// random and sent as the main text in the message.
    pub response_phrases:   Vec<String>,

    /// When composing a response, a single file from this list is selected at
    /// random and attached.
    pub response_filenames: Vec<PathBuf>,

    /// The bot will only respond to trigger phrases in this channel list.
    pub bot_channels:       Vec<String>,
}

enum BotState {
    Waiting(Instant),
    Listening,
}

impl BotState {
    pub fn cooldown_expired(&self) -> bool {
        match self {
            BotState::Waiting(ref then) => *then <= Instant::now(),
            BotState::Listening         => true,
        }
    }
}

/// State for a Handler
struct HandlerInner {
    /// User ID for this bot
    pub user_id:          u64,

    /// User name for this bot
    pub user_name:        String,

    /// After sending a response to a trigger phrase, the bot will not send another
    /// response until this duration has passed.
    pub cooldown:         Duration,

    // The bot has a cooldown period before responding.
    // This state management is encoded in 'state'.
    /// Whether the bot is on cooldown or not
    pub state:            BotState,

    /// A list of phrases that the bot will respond to
    pub triggers:         Vec<String>,

    /// A list of messages that the bot will choose from to respond to a trigger phrase.
    /// This response is paired with a file from `resp_files`.
    pub resp_text:        Vec<String>,

    /// A list of file paths that the bot will choose from to respond to a trigger phrase.
    /// This response is paired with a message from `resp_text`.
    pub resp_files:       Vec<PathBuf>,

    /// The bot will only process messages from these channels.
    /// Note: Do not include the `#` in a channel name. e.g. use `general`, not `#general`.
    pub allowed_channels: Vec<String>,
}

impl HandlerInner {
    fn filter_matches(&self, msg: &Message) -> bool {
        // If the message is NOT from an allowed channel,
        // the filter must fail.
        if self.allowed_channels.iter()
            .find(|c| {
                if let Some(ref name) = msg.channel_id.name() {
                    str::eq_ignore_ascii_case(&c, name)
                } else {
                    // I don't know why a channel name would be None,
                    // but if it is we can't do much about it.
                    eprintln!("Unable to find channel name for channel_id {}",
                              msg.channel_id.as_u64());
                    false
                }
            })
            .is_none() {
            return false;
        }

        // If the message does NOT contain a trigger phrase,
        // the filter must fail.
        if self.triggers.iter()
            .find(|trigger| {
                msg.content
                    .to_ascii_lowercase()
                    // trigger should have already been lowercased on load.
                    .contains(trigger.as_str())
            })
            .is_none() {
            return false;
        }

        // We have nothing else to check.
        // Anything that makes it here passes the filter.
        true
    }
}

struct Handler {
    inner: Mutex<RefCell<HandlerInner>>,
}

impl Handler {
    fn new(inner: HandlerInner) -> Handler {
        Handler {
            inner: Mutex::new(RefCell::new(inner))
        }
    }

    /// Log a message from the server that the bot's on.
    #[allow(dead_code)]
    fn log_msg(msg: &Message) {
        let username = msg.author.name.as_str();
        let text = msg.content.as_str();

        let channel = msg.channel_id.name().unwrap_or_default();
        println!(
            " #{channel:<9} [{user}] \"{text}\"",
            channel=channel,
            user=username,
            text=text
        );
    }
}

impl EventHandler for Handler {
    // Event handlers are dispatched through a threadpool, and so multiple
    // events can be dispatched simultaneously.
    fn message(&self, _ctx: Context, msg: Message) {
        // This is really useful for debugging, but otherwise kind of creepy.
        // It doesn't need to access any Inner data, so we can do this before grabbing the lock.
        //Handler::log_msg(&msg);

        let lock = self.inner.lock().unwrap();
        let mut inner = lock.borrow_mut();

        if msg.author.id.0 == inner.user_id {
            // Ignore our own messages.
            return;
        }

        if inner.filter_matches(&msg) {
            // If the cooldown has expired, update it here.
            // It helps keep the match block simple.
            if inner.state.cooldown_expired() {
                inner.state = BotState::Listening;
            }
            match inner.state {
                BotState::Listening => {
                    let mut rng = thread_rng();

                    // Select an expression and a file at random.
                    // If either of these are empty, they are omitted from the response.
                    // If they're both empty, or if the file doesn't exist on disk,
                    // we early-return and do not send a message.
                    let o_text = inner.resp_text.as_slice().choose(&mut rng);
                    let o_file = inner.resp_files.as_slice().choose(&mut rng);
                    if let Err(err) = msg
                        .channel_id
                        .send_files(
                            o_file.iter().map(|pb| pb.as_path()),
                            |mut m: serenity::builder::CreateMessage| {
                                if let Some(text) = o_text {
                                    m = m.content(text);
                                }
                                m
                            }
                        ) {
                        eprintln!("Failed to send file and message: {:#?}", err);
                        return;
                    }
                    // `send_files` will return early if it fails, so we only update the state here
                    // after we know a response has been sent.
                    inner.state = BotState::Waiting(Instant::now() + inner.cooldown);
                }
                // We should respond to this, but we're in cooldown so we won't.
                BotState::Waiting(ref then) => {
                    let remaining = *then - Instant::now();
                    println!(
                        "Ignoring message until cooldown finishes: {}.{:0>2} seconds left",
                        remaining.as_secs(),
                        remaining.subsec_nanos() / 10_000_000);
                }
            }
        }
    }

    // Set a handler to be called on the `ready` event. This is called when a
    // shard is booted, and a READY payload is sent by Discord. This payload
    // contains data like the current user's guild Ids, current user data,
    // private channels, and more.
    //
    // In this case, just print what the current user's username is.
    fn ready(&self, _: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);
        let lock = self.inner.lock().unwrap();
        let mut inner = lock.borrow_mut();
        inner.user_id = ready.user.id.0;
        inner.user_name = ready.user.name;
    }
}

fn load_config(json_string: &str) -> Result<HandlerInner, Error> {
    let user_config: UserConfig = serde_json::from_str(json_string)?;

    // We don't do any sanity checks for the cooldown - it's pretty straight forward.
    let cooldown = Duration::from_millis((1e3 * user_config.cooldown) as u64);

    // Warn if someone includes a "#" in the channel name, since the name comparisions happen
    // without the leading "#".
    let allowed_channels: Vec<String> = user_config.bot_channels;
    for channel in &allowed_channels {
        if channel.starts_with("#") {
            println!(
                "[WARNIGN] Channel name starts with '#', but probably shouldn't: {}",
                channel
            );
        }
    }

    // Store the trigger phrases in lower case, to ease case-insensitive comparisons.
    let triggers: Vec<String> = user_config.trigger_phrases
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let resp_text: Vec<String> = user_config.response_phrases;
    let resp_files: Vec<PathBuf> = user_config.response_filenames;
    {
        let mut not_found = vec![];
        for path in &resp_files {
            if !path.exists() {
                not_found.push(path);
            }
        }
        if !not_found.is_empty() {
            bail!("Could not find the following files: {:?}", &not_found);
        }
    }
    if resp_text.is_empty() && resp_files.is_empty() {
        bail!("There are no response files OR response phrases in the configuration.");
    }

    Ok(HandlerInner {
        cooldown,
        allowed_channels,
        triggers,
        resp_text,
        resp_files,

        user_id: 0,
        user_name: "".to_string(),
        state: BotState::Listening,
    })
}

fn main() -> Result<(), Box<error::Error>> {
    let id:          u64 = 539280999402438678;
    let permissions: u32 = 117760;
    println!(
        "https://discordapp.com/oauth2/authorize?client_id={}&scope=bot&permissions={}",
        id,
        permissions);

    // Configure the client with your Discord bot token in the environment.
    let token = env::var("DISCORD_TOKEN")
        .expect("Set DISCORD_TOKEN before launching the bot");

    let mut file = fs::File::open("config.json")?;
    let mut json_string = String::new();
    file.read_to_string(&mut json_string)?;
    println!("{}", json_string);

    let inner = load_config(&json_string)?;
    let mut client = Client::new(&token, Handler::new(inner))?;
    client.start()?;

    Ok(())
}
