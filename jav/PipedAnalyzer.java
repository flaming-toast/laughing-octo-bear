import java.io.*; import java.util.*;
/* Demonstrate piped streams. Data is read from file and then read
   and "analysized" by one thread, which in turn passes its result
   via a pipe to a second thread for further analysis. This thread
   in turn passes its data via a pipe to a method for output to a file. */
public class PipedAnalyzer {

  public static void main(String[] args) throws IOException {

    File file = null;

     // Get the file from the argument line.
    if (args.length > 0) file = new File (args[0]);
    if (file == null) {
      System.out.println ("Input data file required");
      System.exit (0);
    }
    // Create a file reader for the data file.
    FileReader file_in = new FileReader (file);

    // Carry out the two levels of analysis and then
    // write out the results.
    analyzeOut (analyze2 (analyze1 (file_in)));

    // Close the file stream.
    file_in.close();

  } // main

  /* Set up the piped streams for the first thread.
     Then create and start the thread. */
  public static Reader analyze1 (Reader source)
       throws IOException {

    // Buffer the input data.
    BufferedReader buf_in = new BufferedReader (source);

    // Create a pipe for data sent out by the Analyze1Thread
    PipedWriter pipe_out = new PipedWriter ();

    // What goes into the pipe can be read by the other thread via pipe_in
    PipedReader pipe_in = new PipedReader (pipe_out);

    // Start the thread for the first level analysis. It
    // will take data from buf_in and write it into pipe_out.
    new Analyze1Thread (pipe_out, buf_in).start ();

    // The other thread will be able to read via pipe_in what
    // was written into pipe_out.
    return pipe_in;

  } // analyze1

  /* Set up the piped streams for the second thread.
     Then create and start the thread. */
  public static Reader analyze2 (Reader source) throws IOException {

    // Buffer the input data.
    BufferedReader buf_in = new BufferedReader (source);

    // Create a pipe for data sent out by the Analyze2Thread
    PipedWriter pipe_out = new PipedWriter ();

    // What goes into the pipe can be read by the other thread via pipe_in
    PipedReader pipe_in = new PipedReader (pipe_out);

    // Start the thread for the second level analysis. It
    // will take data from buf_in and write it into pipe_out.
    new Analyze2Thread  (pipe_out, buf_in).start ();

    // The other thread will be able to read via pipe_in what
    // was written into pipe_out.
    return pipe_in;

  } // analyze2

  /* Read the output from the final analysis step and print to console. */
  public static void analyzeOut (Reader source) throws IOException {

    // Buffer the input data.
    BufferedReader buf_in = new BufferedReader (source);
    System.out.println ("PipedAnalysis Output:");

    String result;
    while ((result = buf_in.readLine ()) != null)
         System.out.println (result);
    buf_in.close ();

  } // analyzeOut

} // PipedAnalyzer

/* Helper class for PipedAnalyzer. Illustrates how a first level
   of analysis would be done on data in a sequence of threads
   connected by piped streams. */
class Analyze1Thread extends Thread {
  private PrintWriter fOut;
  private Scanner fScanner;

  public Analyze1Thread (Writer out, BufferedReader in) {
      fOut = new PrintWriter (out);
      fScanner  = new Scanner (in);
  }

  /* Read through data until it runs out. Do calculation
     on each value and send result to the output stream. */
   public void run () {
    double d = 0.0;
    if (fOut != null && fScanner != null) {
      try {
        while (true) {
          d = fScanner.nextDouble ();
          // Send as string to the PrintWriter stream
          fOut.printf ("%12.5f %n",calculate (d));
          fOut.flush ();
        }
      }
      catch (NoSuchElementException nse)
      {} // data finished
      catch (Exception e) {
             System.err.println("Analyzer1Thread error = " + e);
      }
    }
    fOut.close ();
  } // run

  /* Do trivial calculation. */
  double calculate (double d) {return d*d;}

} // Analyze1Thread

/* Helper class for PipedAnalyzer. Illustrates the second level of
   analysis on data in a sequence of threads connected by piped streams. */
class Analyze2Thread extends Thread {
  private PrintWriter fOut;
  private Scanner fScanner;

  public Analyze2Thread (Writer out, BufferedReader in) {
      fOut = new PrintWriter (out);
      fScanner  = new Scanner (in);
  } // ctor

  /* Read through the data until it runs out. Do calculation
     on each value and send the result to the output stream. */
  public void run () {
    double d = 0.0;
    if (fOut != null && fScanner != null) {
      try {
        while (true) {
          d = fScanner.nextDouble ();
          // Print as string to the PrintWriter stream.
          fOut.printf ("%12.5f %n",calculate (d));
          fOut.flush ();
        }
      }
      catch (NoSuchElementException nse)
      {} // data finished
      catch (Exception e) {
             System.err.println("Analyzer1Thread error = " + e);
      }
    }
    fOut.close ();
  } // run

  /* Do trivial calculation. */
  double calculate (double d) {return 2.0 * d;}

} // Analyze2Thread
