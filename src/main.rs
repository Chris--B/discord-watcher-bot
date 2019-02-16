extern crate serenity;

use std::{
    cell::RefCell,
    env,
    error,
    path::PathBuf,
    str,
    sync::Mutex,
    time::{
        Instant,
        Duration,
    },
};

use serenity::{
    prelude::*,
    model::channel::Message,
    model::gateway::Ready,
};

enum BotState {
    Waiting(Instant),
    Listening,
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
                msg.content.contains(trigger.as_str())
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
    fn log_msg(msg: &Message) {
        let username = msg.author.name.as_str();
        let text = msg.content.as_str();

        let channel = msg.channel_id.name()
            .unwrap_or_default();
        println!(
            "#{channel:<10} [{user}] \"{text}\"",
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
        Handler::log_msg(&msg);
        let lock = self.inner.lock().unwrap();
        let mut inner = lock.borrow_mut();

        if msg.author.id.0 == inner.user_id {
            // Ignore our own messages.
            return;
        }

        if !inner.filter_matches(&msg) {
            print!("Ignoring this:\t");
            Handler::log_msg(&msg);
            return;
        }
        match inner.state {
            BotState::Listening => {
                let now = Instant::now();
                inner.state = BotState::Waiting(now + inner.cooldown);
                if let Err(why) = msg.channel_id.send_files(
                    ["buddy.png"].iter().cloned(),
                    |m| m.content("You called?")
                ) {
                    eprintln!("Failed to send file: {:#?}", why);
                }
            }
            BotState::Waiting(ref then) => {
                let remaining = *then - Instant::now();
                println!(
                    "Ignoring valid request until cooldown finishes: {}.{:0>2} seconds left",
                    remaining.as_secs(),
                    remaining.subsec_nanos() / 10_000_000);
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

fn main() -> Result<(), Box<error::Error>> {
    let id:          u64 = 539280999402438678;
    let permissions: u32 = 117760;
    println!(
        "Add me to things: https://discordapp.com/oauth2/authorize?client_id={}&scope=bot&permissions={}",
        id,
        permissions);

    // Configure the client with your Discord bot token in the environment.
    let token = env::var("DISCORD_TOKEN")
        .expect("Expected a token in the environment");
    // Create a new instance of the Client, logging in as a bot. This will
    // automatically prepend your bot token with "Bot ", which is a requirement
    // by Discord for bot users.

    let inner = HandlerInner {
        user_id: 0,
        user_name: "".to_string(),
        cooldown:         Duration::from_secs(10),
        allowed_channels: vec!["test".to_string()], // This must not start with '#'!
        triggers:         vec!["jesus".to_string(), "christ".to_string()],
        resp_text:        vec!["You called?".to_string()],
        resp_files:       vec!["buddy.png".into()],
        state:            BotState::Listening,
    };
    let handler = Handler {
        inner: Mutex::new(RefCell::new(inner))
    };
    let mut client = Client::new(&token, handler)?;

    // Finally, start a single shard, and start listening to events.
    //
    // Shards will automatically attempt to reconnect, and will perform
    // exponential backoff until it reconnects.
    if let Err(why) = client.start() {
        println!("Client error: {:#?}", why);
    }

    Ok(())
}