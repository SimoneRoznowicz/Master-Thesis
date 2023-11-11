use std::sync::mpsc;
use std::thread;
use std::time::Duration;

// Message enum to represent the messages sent between nodes
#[derive(Debug)]
enum Message {
    Start,
    Stop,
}

fn do_something_callback() {
    println!("Node B is performing some final actions in the callback...");
    // Add your actual logic here
}

fn node_a(sender: mpsc::Sender<Message>) {
    // Node A keeps sending messages to B until it receives a stop message
    for _ in 0..10 {
        // Sending a start message
        sender.send(Message::Start).unwrap();
        // Simulating some work
        thread::sleep(Duration::from_secs(1));
    }

    // Sending a stop message
    sender.send(Message::Stop).unwrap();
}

fn node_b(receiver: mpsc::Receiver<Message>, callback: impl Fn()) {
    // Node B keeps receiving messages from A until it receives a stop message
    while let Ok(message) = receiver.recv() {
        match message {
            Message::Start => {
                println!("Node B received a start message and is processing...");
                // Simulating some work
                thread::sleep(Duration::from_secs(2));
            }
            Message::Stop => {
                println!("Node B received a stop message. Performing final actions...");
                callback(); // Call the provided callback
                break;
            }
        }
    }
}

fn main() {
    // Create a channel for communication between nodes
    let (sender, receiver) = mpsc::channel();

    // Spawn threads for node A and node B with a callback
    let handle_a = thread::spawn(|| node_a(sender.clone()));
    let handle_b = thread::spawn(|| node_b(receiver, || do_something_callback()));

    // Wait for both threads to finish
    handle_a.join().unwrap();
    handle_b.join().unwrap();
}
