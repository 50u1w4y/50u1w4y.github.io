# Welcome to MkDocs

For full documentation visit [mkdocs.org](https://mkdocs.org).

## Commands

* `mkdocs new [dir-name]` - Create a new project.
* `mkdocs serve` - Start the live-reloading docs server.
* `mkdocs build` - Build the documentation site.
* `mkdocs help` - Print this help message.

## Project layout

    mkdocs.yml    # The configuration file.
    docs/
        index.md  # The documentation homepage.
        ...       # Other markdown pages, images and other files.
		
		
<!-- Gitalk start  -->

<!-- Link Gitalk -->
<link rel="stylesheet" href="https://unpkg.com/gitalk/dist/gitalk.css">
<script src="https://unpkg.com/gitalk@latest/dist/gitalk.min.js"></script> 
<div id="gitalk-container"></div>     
<script type="text/javascript">
    var gitalk = new Gitalk({
	
		clientID: 'd918413ad93a14f36876',
		clientSecret: '9c5740494e6c1c792df208d8abed35ef2bfd855d',
		repo: 'comment',
		owner: '50u1w4y',
		admin: ['50u1w4y'],
		id: md5(location.pathname),
		distractionFreeMode: true,
    
    });
    gitalk.render('gitalk-container');
</script> 
<!-- Gitalk end -->
