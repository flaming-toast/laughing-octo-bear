class fifo
{
  static boolean running=true;
  static QueueManager queueManager=new QueueManager();
  public static void main(String[] args){
    //instantiate and start two threads
    Thread producer=new Producer();
    Thread consumer=new Consumer();
    producer.start(); consumer.start();
    try{Thread.currentThread().sleep(2000);}
    catch(InterruptedException e){};
    running=false;//signal the threads to terminate
  }
}//end class fifo
//======================================================
class Producer extends Thread
{
  public void run()
  {
    byte byteToStore;
    //Loop until running goes false
    while (fifo.running){
      //get a data byte
      byteToStore=(byte)(Math.random()*128);
      //Invoke the synchronized method to put the byte
      // in the queue
      fifo.queueManager.putByteInQueue(byteToStore);
      //delay a random period of time
      try{Thread.currentThread().sleep((int)(Math.random()*100));}
      catch(InterruptedException e){};
    }//end while statement
    System.out.println("Terminating Producer run method");
  }//end run method
}//end class producer
//======================================================
class Consumer extends Thread
{
  public void run()
  {
    byte dataFromQueue;
    //Loop until running goes false
    while (fifo.running) {
      dataFromQueue=fifo.queueManager.getByteFromQueue();
      try{Thread.currentThread().sleep((int)(Math.random()*100));}
      catch(InterruptedException e){};
    }//end while statement
    System.out.println("Terminating Consumer run method");
  }//end run method
}//end class consumer
//======================================================
class QueueManager
{
  Queue queue;
  QueueManager() {queue=new Queue();}
  synchronized void putByteInQueue(byte incomingByte){
    //This synchronized method places a byte in the queue
    // If the queue is full, wait(). If still full when
    // wait() terminates, wait again. Called by the
    // producer thread to put a byte in the queue.
    try{while(queue.isFull())
         {System.out.println("Queue full, waiting");wait();}}
    catch (InterruptedException E)
         {System.out.println("InterruptedException: " + E);}
    queue.enQueue(incomingByte); notify();
  }
  public synchronized byte getByteFromQueue(){
    //This synchronized method removes a byte from the
    // queue. If the queue is empty, wait(). If still
    // empty when wait() terminates, wait again. Called by
    // consumer thread to get a byte from the queue
    try{while(queue.isEmpty())
         {System.out.println("Queue empty, waiting");wait();}}
    catch (InterruptedException E)
         {System.out.println("InterruptedException: " + E);
    }
    byte data=queue.deQueue();
    notify(); return data;
  }
}//end class QueueManager
//======================================================
//This is a standard FIFO queue class.
class Queue{
    static final int MAXQUEUE=4; byte[] queue=new byte[MAXQUEUE];
    int front, rear; Queue(){front=rear=0;}
    void enQueue(byte item){queue[rear]=item; rear=next(rear);}
    byte deQueue(){byte temp=queue[front];front=next(front);return temp;}
    boolean isEmpty(){return front == rear;}
    boolean isFull(){return (next(rear) == front);}
    int next(int index){return (index+1 < MAXQUEUE ? index+1 : 0);}
}//end Queue class
