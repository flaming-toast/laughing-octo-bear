import java.awt.*; import java.awt.event.*; import javax.swing.*;

class NewThread implements Runnable
{
  Thread t; boolean suspendThread; long x = 0;
  public NewThread()
  {
    t=new Thread(this); suspendThread=false; t.start();
  }
  public void run() //Thread code runs a counter
  {
System.out.println("Thread running");
    while(true) // run it forever
    {
      try
      { Thread.sleep(1000);
        synchronized(this){while(suspendThread){wait();}}
      }
      catch(InterruptedException e)
      {System.out.println("Thread paused!");}
      finally {SyncThread.label.setText(" Seconds Passed: " + x++);}
    }
  }
  void mySuspend() {suspendThread=true;}
  synchronized void myResume() {suspendThread=false;notify();}
}

public class SyncThread extends JFrame // main program
{
  //Declare GUI components
  static NewThread count;
  static JLabel label = new JLabel("",JLabel.LEFT);
  JButton resume = new JButton("Resume");
  JButton pause = new JButton("Pause");
  JPanel north = new JPanel();
  {
	north.add(resume); north.add(pause);
    this.getContentPane().add("North",north);
    this.getContentPane().add("South",label);
    this.addWindowListener(new WindowHandler());
    resume.addActionListener(new ResumeHandler());
    pause.addActionListener(new PauseHandler());
  }
//main method
  public static void main(String[] args)
  {
    SyncThread app = new SyncThread();
    app.setBounds(200,200,200,100);
    app.setTitle("Synchronized Thread");
    app.setVisible(true);
    count=new NewThread();
  }
  // start defining inner class error handlers -------
  class WindowHandler extends WindowAdapter
  {public void windowClosing(WindowEvent e) {System.exit(1);}}
  class ResumeHandler implements ActionListener
  {
  public synchronized void actionPerformed(ActionEvent e)
  {
    System.out.println("Resume pressed!");
    count.myResume();}
  }
  class PauseHandler implements ActionListener
  {
  public synchronized void actionPerformed(ActionEvent e)
  {
    System.out.println("Pause pressed!");
	count.mySuspend();}
  }// end inner class error handlers ----------------
} // end main program class
