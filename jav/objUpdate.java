/* objUpdate.java uses a collection to store objects -- March 18 2006
   and shows how to read and write file objects using serialization
   Concepts such as swing, events, exceptions and ArrayList are used. */
import java.awt.*; import java.awt.event.*; import javax.swing.*;
import java.io.*; import java.util.*; import java.text.*;
public class objUpdate extends JFrame
{
  final String DB = "data.obj"; // parameterize the file name
  //declare an ArrayList collection object
  ArrayList <Person> persons = new ArrayList<Person>(); //generic typing
  //variables needed to maintain Person objects in ArrayList collection
  Person p; int index = 0;
  //variable used to format Date objects
  SimpleDateFormat f = new SimpleDateFormat("MM/dd/yyyy");
  //GUI components
  JTextField n = new JTextField(15);
  JTextField d = new JTextField(15);
  JButton next = new JButton("Next");
  JButton newPerson=new JButton("New Person");
  public objUpdate()
  {
    super("Person"); setBounds(150,150,200,120);
    setResizable(false); setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
    Container con = this.getContentPane();
    con.setLayout(new FlowLayout());
    con.add(n); con.add(d);
    next.setMnemonic('N'); newPerson.setMnemonic('P');
    con.add(next); con.add(newPerson);
    this.addWindowListener(new Window());
    next.addActionListener(new Next());
    newPerson.addActionListener(new NewPerson()); setVisible(true);
  }
  //event handlers
  class Window extends WindowAdapter
  {
    public void windowOpened(WindowEvent e) //read file on start
    {
      FileInputStream in = null;ObjectInputStream data = null;
      try
      {
        in=new FileInputStream(DB);data=new ObjectInputStream(in);
        p = (Person) data.readObject();
        while( p != null)
        {
          persons.add(p); //store Person object in ArrayList collection
          p = (Person) data.readObject(); //read the next record
        }
        data.close();
      }
      catch(Exception ex)
      {
        // IOException will always occur on the last read above
      }
      finally {if(persons.size()>0) displayRecord();}
    }
    public void windowClosing(WindowEvent e) //write file on finish
    {
      FileOutputStream out=null;ObjectOutputStream data=null;
      try
      {
        //open file for output
        out=new FileOutputStream(DB);data=new ObjectOutputStream(out);
        //write Person objects to file using iterator class
        Iterator <Person> itr = persons.iterator();
        while (itr.hasNext()) {data.writeObject((Person) itr.next());}
      data.flush(); data.close();
      }
      catch(Exception ex)
      {
        JOptionPane.showMessageDialog(objUpdate.this,
        "Error processing output file"+"\n"+ex.toString(),
        "Output Error",JOptionPane.ERROR_MESSAGE);
      }
      finally {System.exit(0);}
    }
  }
  class Next implements ActionListener
  {
    public void actionPerformed(ActionEvent e)
    {
      //move to the next record or first record
      if(persons.size()>0)
      {
        index++; index=(index>=persons.size()) ? 0 : index;
        displayRecord();
      }
    }
  }
  class NewPerson implements ActionListener
  {
    public void actionPerformed(ActionEvent e)
    {
      String name = null;
      name = JOptionPane.showInputDialog(objUpdate.this,
          "Enter a name (eg. John Russell)","Input Person",
          JOptionPane.QUESTION_MESSAGE);
      if(!(name == null))
      {
         //prompt the user for a date
         String date = null;
         date = JOptionPane.showInputDialog(objUpdate.this,
           "Enter Date (eg. 06/17/1946)","Input Person",
           JOptionPane.QUESTION_MESSAGE);
         if(!(date == null))
         {
           //convert String to Date
           try
           {
             Date d = f.parse(date);
             p=new Person(name,d); persons.add(p);
             index=persons.lastIndexOf(p); displayRecord();
           }
           catch(ParseException ex)
           {
             JOptionPane.showMessageDialog(objUpdate.this,
             "Invalid date format!","Input Error",JOptionPane.ERROR_MESSAGE);
           }
        }
      }
    }
  }
  //method to display current Person object in the ArrayList
  //uses global index ??
  private void displayRecord()
  {
    p=(Person) persons.get(index);
    n.setText(p.name); d.setText(f.format(p.date));
  }
  public static void main(String[] args) {new objUpdate();}
}
//an OUTER class that defines a serialized Person class
class Person implements Serializable
{
  String name; Date date;
  Person(String name,Date date) {this.name = name;this.date = date;}
}
