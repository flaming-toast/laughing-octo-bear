import java.awt.*; import java.awt.event.*; import javax.swing.*;
public class SimpleThread extends JFrame implements Runnable
{
  //Declare a Thread object - must pass in a reference to
  //class that contains the thread's run method
  Thread count = new Thread(this);
  int number = 0;
  public SimpleThread()
  {
    //register a window event
    this.addWindowListener(new Window());
    count.start(); //start the thread
  }
  //override the paint method to draw a number
  public void paint(Graphics g)
  {
    g.clearRect(0,0,this.getWidth(),this.getHeight());
    g.drawString("" + number,this.getWidth()/2,this.getHeight()/2);
  }
  //window event
  class Window extends WindowAdapter
    {public void windowClosing(WindowEvent e) {System.exit(1);}}

  //Thread code
  public void run()
  {
    while(true) // run it forever
    {
      try
      {
		  count.sleep(1000); // 1000 = 1 sec
      }
      catch(Exception e) {} //do nothing
      finally {number++;repaint();}
    }
  }
  //main method
  public static void main(String[] args)
  {
    SimpleThread app = new SimpleThread();
    app.setBounds(200,200,150,100);
    app.setTitle("Simple Thread");
    app.setVisible(true);
  }
}